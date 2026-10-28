// SPDX-License-Identifier: LGPL-2.0-or-later
#include "prompt.hpp"
#include <algorithm>
#include <chrono>
#include <fcntl.h>
#include <glib.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef DOME_NATIVE_PINENTRY
#define DOME_NATIVE_PINENTRY "/usr/local/libexec/domed/pinentry-fltk"
#endif
namespace dw {
namespace {
    thread_local bool active = false, cancelled = false;
    thread_local std::function<void()> finished;
}
bool prompt_active() { return active; }
void cancel_prompt()
{
    if (active)
        cancelled = true;
}
void prompt_finished(std::function<void()> callback) { finished = std::move(callback); }
struct PromptScope {
    PromptScope()
    {
        if (active)
            throw Error("Nested credential prompt refused");
        active = true;
        cancelled = false;
    }
    ~PromptScope()
    {
        active = false;
        cancelled = false;
        if (finished)
            finished();
    }
};
void pump()
{
    while (g_main_context_pending(nullptr))
        g_main_context_iteration(nullptr, false);
    if (cancelled)
        throw Error("Credential prompt cancelled");
}

void harden()
{
    rlimit r { 0, 0 };
    setrlimit(RLIMIT_CORE, &r);
    prctl(PR_SET_DUMPABLE, 0);
}
namespace {
    std::string escape(const std::string& s)
    {
        std::string out;
        const char* h = "0123456789ABCDEF";
        for (unsigned char c : s) {
            if (c == '%' || c == '\n' || c == '\r' || c < 32) {
                out += '%';
                out += h[c >> 4];
                out += h[c & 15];
            } else
                out += c;
        }
        return out;
    }
    struct Child {
        pid_t pid = -1;
        int in = -1, out = -1;
        ~Child()
        {
            if (in >= 0)
                close(in);
            if (out >= 0)
                close(out);
            if (pid > 0) {
                int status;
                if (waitpid(pid, &status, WNOHANG) == 0) {
                    kill(pid, SIGTERM);
                    for (int i = 0; i < 20; i++) {
                        if (waitpid(pid, &status, WNOHANG) == pid)
                            return;
                        usleep(10000);
                    }
                    kill(pid, SIGKILL);
                    waitpid(pid, &status, 0);
                }
            }
        }
    };
}
std::optional<Bytes> pinentry(const std::string& title, const std::string& description, bool confirm, bool repeat)
{
    PromptScope scope;
    if (title.size() > 4096 || description.size() > 32768)
        throw Error("Prompt metadata too large");
    Child child;
    int input[2], output[2];
    if (pipe2(input, O_CLOEXEC))
        throw Error("Cannot create prompt pipe");
    if (pipe2(output, O_CLOEXEC)) {
        close(input[0]);
        close(input[1]);
        throw Error("Cannot create prompt pipe");
    }
    child.pid = fork();
    if (child.pid < 0) {
        for (int fd : { input[0], input[1], output[0], output[1] })
            close(fd);
        throw Error("Cannot start credential helper");
    }
    if (child.pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        if (getppid() == 1)
            _exit(127);
        dup2(input[0], 0);
        dup2(output[1], 1);
        int null = open("/dev/null", O_WRONLY);
        if (null >= 0)
            dup2(null, 2);
        for (int fd : { input[0], input[1], output[0], output[1], null })
            if (fd > 2)
                close(fd);
        execl(DOME_NATIVE_PINENTRY, DOME_NATIVE_PINENTRY, static_cast<char*>(nullptr));
        _exit(127);
    }
    close(input[0]);
    close(output[1]);
    child.in = input[1];
    child.out = output[0];
    if (fcntl(child.in, F_SETFL, fcntl(child.in, F_GETFL) | O_NONBLOCK) < 0)
        throw Error("Cannot configure prompt pipe");
    auto deadline = std::chrono::steady_clock::now() + std::chrono::minutes(3);
    Bytes pending;
    bool data_seen = false;
    auto send = [&](const std::string& s) {
        size_t n = 0;
        while (n < s.size()) {
            pump();
            auto result = write(child.in, s.data() + n, s.size() - n);
            if (result < 0 && errno == EAGAIN) {
                auto ms
                    = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now())
                          .count();
                if (ms <= 0)
                    throw Error("Credential prompt timed out");
                pollfd p { child.in, POLLOUT, 0 };
                poll(&p, 1, std::min<long>(ms, 50));
                continue;
            }
            if (result < 0 && errno == EINTR)
                continue;
            if (result <= 0)
                throw Error("Credential helper pipe failed");
            n += result;
        }
    };
    auto response = [&]() -> std::optional<Bytes> {
        data_seen = false;
        Bytes data;
        size_t total = 0;
        for (;;) {
            pump();
            Bytes line;
            for (;;) {
                if (pending.empty()) {
                    pump();
                    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        deadline - std::chrono::steady_clock::now())
                                  .count();
                    pollfd p { child.out, POLLIN, 0 };
                    if (ms <= 0)
                        throw Error("Credential prompt timed out");
                    if (poll(&p, 1, std::min<long>(ms, 50)) < 0) {
                        if (errno == EINTR)
                            continue;
                        throw Error("Credential prompt poll failed");
                    }
                    if (!(p.revents & (POLLIN | POLLHUP)))
                        continue;
                    unsigned char buffer[1024];
                    auto n = read(child.out, buffer, sizeof(buffer));
                    if (n <= 0)
                        throw Error("Credential helper stopped");
                    pending.insert(pending.end(), buffer, buffer + n);
                    explicit_bzero(buffer, sizeof(buffer));
                }
                auto it = std::find(pending.begin(), pending.end(), '\n');
                size_t count = it - pending.begin();
                line.insert(line.end(), pending.begin(), pending.begin() + count);
                if (line.size() > 65536 || total + line.size() > 262144)
                    throw Error("Credential helper response too large");
                bool complete = it != pending.end();
                pending.erase(pending.begin(), pending.begin() + count + (complete ? 1 : 0));
                if (complete)
                    break;
            }
            total += line.size();
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            auto prefix = [&](const char* s) {
                size_t n = strlen(s);
                return line.size() >= n && std::equal(line.begin(), line.begin() + n, s);
            };
            if (prefix("OK") && (line.size() == 2 || line[2] == ' '))
                return data;
            if (prefix("ERR "))
                return std::nullopt;
            if (prefix("D ")) {
                data_seen = true;
                for (size_t i = 2; i < line.size(); i++) {
                    unsigned char c = line[i];
                    auto hex = [](unsigned char b) -> int {
                        if (b >= '0' && b <= '9')
                            return b - '0';
                        if (b >= 'A' && b <= 'F')
                            return b - 'A' + 10;
                        if (b >= 'a' && b <= 'f')
                            return b - 'a' + 10;
                        return -1;
                    };
                    if (c == '%') {
                        if (i + 2 >= line.size() || hex(line[i + 1]) < 0 || hex(line[i + 2]) < 0)
                            throw Error("Malformed credential response");
                        c = hex(line[i + 1]) * 16 + hex(line[i + 2]);
                        i += 2;
                    }
                    data.push_back(c);
                    if (data.size() > 65536)
                        throw Error("Credential response too large");
                }
            } else if (prefix("INQUIRE ")) {
                send("END\n");
            } else if (!prefix("S ") && !prefix("#"))
                throw Error("Unexpected credential helper response");
        }
    };
    if (!response())
        return std::nullopt;
    auto command = [&](const std::string& s) {
        send(s + "\n");
        return response();
    };
    if (!command("SETTIMEOUT 180") || !command("SETTITLE " + escape(title))
        || !command("SETDESC " + escape(description)))
        return std::nullopt;
    if (confirm)
        return command("CONFIRM");
    if (!command("SETPROMPT Wallet password:"))
        return std::nullopt;
    if (repeat && !command("SETREPEAT Repeat wallet password:"))
        return std::nullopt;
    auto value = command("GETPIN");
    if (value && !data_seen)
        throw Error("Credential helper omitted secret data");
    return value;
}
}

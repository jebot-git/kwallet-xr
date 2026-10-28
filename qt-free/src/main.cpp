// SPDX-License-Identifier: LGPL-2.0-or-later
#include "bus.hpp"
#include "prompt.hpp"
#include <csignal>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
namespace {
void ready(int fd)
{
    pollfd p { fd, POLLIN, 0 };
    if (poll(&p, 1, 90000) <= 0)
        throw dw::Error("PAM handoff timed out");
}
dw::Bytes pam(int hashfd, int envfd)
{
    if (hashfd < 0 || envfd < 0 || hashfd == envfd)
        throw dw::Error("Invalid PAM descriptors");
    dw::Bytes hash(56);
    size_t n = 0;
    while (n < hash.size()) {
        ready(hashfd);
        auto got = read(hashfd, hash.data() + n, hash.size() - n);
        if (got <= 0)
            throw dw::Error("Incomplete PAM key");
        n += got;
    }
    close(hashfd);
    ready(envfd);
    int fd = accept4(envfd, nullptr, nullptr, SOCK_CLOEXEC);
    close(envfd);
    if (fd < 0)
        throw dw::Error("Cannot accept PAM environment");
    ucred peer {};
    socklen_t size = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) || peer.uid != getuid()) {
        close(fd);
        throw dw::Error("Invalid PAM environment peer");
    }
    std::string environment;
    for (;;) {
        ready(fd);
        char buf[1024];
        auto got = read(fd, buf, sizeof(buf));
        if (got < 0) {
            close(fd);
            throw dw::Error("Cannot read PAM environment");
        }
        if (!got)
            break;
        environment.append(buf, got);
        if (environment.size() > 65536) {
            close(fd);
            throw dw::Error("PAM environment too large");
        }
    }
    close(fd);
    size_t begin = 0;
    while (begin < environment.size()) {
        auto end = environment.find('\n', begin);
        auto line = environment.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
        auto split = line.find('=');
        if (split != std::string::npos) {
            auto key = line.substr(0, split), value = line.substr(split + 1);
            if (key == "DBUS_SESSION_BUS_ADDRESS" || key == "XDG_RUNTIME_DIR" || key == "DISPLAY"
                || key == "WAYLAND_DISPLAY" || key == "XAUTHORITY" || key == "XDG_CONFIG_HOME"
                || key == "XDG_DATA_HOME")
                setenv(key.c_str(), value.c_str(), 1);
        }
        if (end == std::string::npos)
            break;
        begin = end + 1;
    }
    return hash;
}
}
int main(int argc, char** argv)
{
    try {
        dw::harden();
        if (geteuid() == 0)
            throw dw::Error("Run the wallet backend as the desktop user, never as root");
        signal(SIGPIPE, SIG_IGN);
        std::filesystem::path directory;
        dw::Bytes hash;
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "--version") {
                std::cout << "Dome Wallet native backend 0.1 (Qt-free, KWallet 6 API)\n";
                return 0;
            }
            if (arg == "--storage-dir" && i + 1 < argc)
                directory = argv[++i];
            else if (arg == "--pam-login" && i + 2 < argc) {
                int h = std::stoi(argv[++i]), e = std::stoi(argv[++i]);
                hash = pam(h, e);
            } else
                throw dw::Error("Usage: dome-walletd [--storage-dir DIRECTORY] [--pam-login HASH_FD ENV_FD]");
        }
        if (directory.empty())
            directory = std::filesystem::path(g_get_user_data_dir()) / "kwalletd";
        if (!std::filesystem::exists(directory)) {
            std::filesystem::create_directories(directory);
            chmod(directory.c_str(), 0700);
        }
        dw::Service service(directory);
        if (!hash.empty()) {
            auto& state = service.backend.state(service.backend.default_wallet(true));
            auto wallet = std::make_unique<dw::Wallet>(service.backend.filename(state.name));
            try {
                wallet->open_hashed(hash);
                state.wallet = std::move(wallet);
            } catch (const std::exception&) {
                std::cerr << "PAM could not unlock the wallet; normal credential prompts remain required.\n";
            }
        }
        service.run();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Dome Wallet: " << e.what() << '\n';
        return 1;
    }
}

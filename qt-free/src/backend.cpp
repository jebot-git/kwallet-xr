// SPDX-License-Identifier: LGPL-2.0-or-later
#include "backend.hpp"
#include <ctime>
#include <fstream>
#include <gio/gunixfdlist.h>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>
namespace dw {
CallerProcess::~CallerProcess()
{
    if (fd >= 0)
        ::close(fd);
}
bool CallerProcess::valid() const
{
    pollfd p { fd, POLLIN, 0 };
    if (fd < 0 || poll(&p, 1, 0) != 0)
        return false;
    // A live pidfd prevents PID reuse while inspecting the current executable.
    struct stat exe {}, process {};
    auto root = "/proc/" + std::to_string(pid);
    return !stat(root.c_str(), &process) && process.st_uid == getuid()
        && !stat((root + "/exe").c_str(), &exe) && exe.st_dev == device && exe.st_ino == inode
        && poll(&p, 1, 0) == 0;
}
namespace {
    std::string utf8(Bytes& b)
    {
        if (!g_utf8_validate(reinterpret_cast<const char*>(b.data()), b.size(), nullptr))
            throw Error("Credential is not valid UTF-8");
        return std::string(b.begin(), b.end());
    }
}
void Backend::prune_callers()
{
    for (auto it = callers.begin(); it != callers.end();) {
        if (it->second->valid()) {
            ++it;
            continue;
        }
        for (auto& [name, s] : states)
            s.processes.erase(it->second);
        it = callers.erase(it);
    }
}
std::shared_ptr<CallerProcess> Backend::caller(const std::string& owner)
{
    if (!connection || owner.empty() || owner.front() != ':')
        throw Error("Cannot verify wallet caller");
    prune_callers();
    GUnixFDList* fds = nullptr;
    auto* result = g_dbus_connection_call_with_unix_fd_list_sync(connection, "org.freedesktop.DBus",
        "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetConnectionCredentials",
        g_variant_new("(s)", owner.c_str()), G_VARIANT_TYPE("(a{sv})"), G_DBUS_CALL_FLAGS_NONE,
        3000, nullptr, &fds, nullptr, nullptr);
    std::unique_ptr<GUnixFDList, decltype(&g_object_unref)> fd_list(fds, g_object_unref);
    if (!result)
        throw Error("Wallet caller disconnected or credentials unavailable");
    std::unique_ptr<GVariant, decltype(&g_variant_unref)> reply(result, g_variant_unref);
    std::unique_ptr<GVariant, decltype(&g_variant_unref)> credentials(
        g_variant_get_child_value(result, 0), g_variant_unref);
    guint uid = 0, pid = 0;
    gint index = -1;
    if (!g_variant_lookup(credentials.get(), "UnixUserID", "u", &uid) || uid != getuid())
        throw Error("Wallet caller is not the desktop user");
    // Older buses retain connection-scoped approval. Numeric PIDs and app names
    // alone must never enable cross-connection grants (PID reuse/spoofing).
    if (!g_variant_lookup(credentials.get(), "ProcessID", "u", &pid) || !pid
        || !g_variant_lookup(credentials.get(), "ProcessFD", "h", &index) || !fds)
        return {};
    auto process = std::make_shared<CallerProcess>();
    process->fd = g_unix_fd_list_get(fds, index, nullptr);
    process->pid = pid;
    if (process->fd < 0)
        return {};
    // Resolve the fd in our PID namespace; reject a mismatched/unresolvable PID.
    std::ifstream info("/proc/self/fdinfo/" + std::to_string(process->fd));
    std::string line;
    bool matches = false;
    while (std::getline(info, line))
        if (line.starts_with("Pid:\t"))
            matches = line.substr(5) == std::to_string(pid);
    pollfd p { process->fd, POLLIN, 0 };
    if (!matches || poll(&p, 1, 0) != 0)
        throw Error("Wallet caller process has exited");
    auto exe_path = "/proc/" + std::to_string(pid) + "/exe";
    struct stat exe {};
    auto* path = g_file_read_link(exe_path.c_str(), nullptr);
    if (!path)
        return {}; // Uninspectable sandbox: keep the original connection scope.
    process->executable = path;
    g_free(path);
    if (stat(exe_path.c_str(), &exe))
        return {};
    process->device = exe.st_dev;
    process->inode = exe.st_ino;
    if (!process->valid())
        throw Error("Wallet caller process changed or exited");
    auto found = callers.find(pid);
    if (found != callers.end()) {
        if (found->second->valid() && found->second->device == process->device
            && found->second->inode == process->inode)
            return found->second;
        for (auto& [name, s] : states)
            s.processes.erase(found->second);
        callers.erase(found);
    }
    if (callers.size() >= 256)
        return {};
    callers.emplace(pid, process);
    return process;
}
bool Backend::authorized(const std::string& name, const std::string& owner)
{
    auto process = caller(owner);
    auto& s = state(name);
    return s.wallet && (process ? s.processes.contains(process) : s.owners.contains(owner));
}
Backend::Backend(std::filesystem::path directory)
    : root(std::move(directory))
{
    struct stat s {};
    if (lstat(root.c_str(), &s) || !S_ISDIR(s.st_mode) || s.st_uid != getuid() || (s.st_mode & 0022))
        throw Error("Wallet directory must be owned by the user and not writable by others");
    // Stock KWallet can leave this directory at 0755; tighten it before loading data.
    if ((s.st_mode & 0077) && chmod(root.c_str(), 0700))
        throw Error("Cannot make wallet directory private");
}
bool Backend::enabled() const
{
    auto path = std::filesystem::path(g_get_user_config_dir()) / "kwalletrc";
    GKeyFile* cfg = g_key_file_new();
    g_key_file_load_from_file(cfg, path.c_str(), G_KEY_FILE_NONE, nullptr);
    bool value = !g_key_file_has_key(cfg, "Wallet", "Enabled", nullptr)
        || g_key_file_get_boolean(cfg, "Wallet", "Enabled", nullptr);
    g_key_file_unref(cfg);
    return value;
}
void Backend::idle_close()
{
    prune_callers();
    auto path = std::filesystem::path(g_get_user_config_dir()) / "kwalletrc";
    GKeyFile* cfg = g_key_file_new();
    g_key_file_load_from_file(cfg, path.c_str(), G_KEY_FILE_NONE, nullptr);
    bool close = g_key_file_get_boolean(cfg, "Wallet", "Close When Idle", nullptr);
    int minutes = g_key_file_has_key(cfg, "Wallet", "Idle Timeout", nullptr)
        ? g_key_file_get_integer(cfg, "Wallet", "Idle Timeout", nullptr)
        : 10;
    g_key_file_unref(cfg);
    if (!close)
        return;
    for (auto& [name, state] : states)
        if (state.wallet
            && std::chrono::steady_clock::now() - state.last_access
                > std::chrono::minutes(std::clamp(minutes, 1, 1440)))
            lock(name);
}
std::filesystem::path Backend::filename(const std::string& name) const
{
    if (name.size() > 512)
        throw Error("Wallet name too long");
    return root / (encode_name(name) + ".kwl");
}
std::vector<std::string> Backend::names() const
{
    std::vector<std::string> out;
    for (auto& p : std::filesystem::directory_iterator(root)) {
        if (p.path().extension() == ".kwl" && !p.is_symlink() && p.is_regular_file())
            out.push_back(decode_name(p.path().stem().string()));
    }
    std::sort(out.begin(), out.end());
    return out;
}
std::string Backend::default_wallet(bool local) const
{
    const char* home = g_get_user_config_dir();
    auto path = std::filesystem::path(home) / "kwalletrc";
    GKeyFile* cfg = g_key_file_new();
    g_key_file_load_from_file(cfg, path.c_str(), G_KEY_FILE_NONE, nullptr);
    bool separate = g_key_file_has_key(cfg, "Wallet", "Use One Wallet", nullptr)
        && !g_key_file_get_boolean(cfg, "Wallet", "Use One Wallet", nullptr);
    auto* text = g_key_file_get_string(cfg, "Wallet", local && separate ? "Local Wallet" : "Default Wallet", nullptr);
    std::string out = text && *text ? text : local && separate ? "localwallet" : "kdewallet";
    g_free(text);
    g_key_file_unref(cfg);
    return out;
}
State& Backend::state(const std::string& name)
{
    filename(name);
    auto [it, created] = states.try_emplace(name);
    if (created) {
        it->second.name = name;
        auto p = root / (encode_name(name) + "_attributes.json");
        if (std::filesystem::exists(p)) {
            auto data = read_private(p, 8 * 1024 * 1024);
            it->second.metadata = Json::parse(data.begin(), data.end());
            if (!it->second.metadata.is_object())
                throw Error("Invalid wallet metadata");
        } else
            it->second.metadata = Json::object();
    }
    return it->second;
}
State& Backend::unlock(const std::string& name, const std::string& owner, const std::string& app)
{
    if (!enabled())
        throw Error("KWallet is disabled in configuration");
    auto& s = state(name);
    auto process = caller(owner);
    auto grant = [&] {
        // A prompt pumps the main loop. Recheck before retaining any approval.
        if (caller(owner) != process || (process && !process->valid()))
            throw Error("Wallet caller changed while awaiting approval");
        if (process)
            s.processes.insert(process);
        else
            s.owners.insert(owner);
    };
    auto requester = app + (process
            ? "\nVerified process: " + process->executable + " (PID " + std::to_string(process->pid) + ")"
            : "\nBus connection: " + owner);
    s.last_access = std::chrono::steady_clock::now();
    if (s.wallet) {
        if (!(process ? s.processes.contains(process) : s.owners.contains(owner))) {
            auto approved
                = pinentry("Wallet access", requester + "\nRequests access to wallet “" + name + "”.", true);
            if (!approved)
                throw Error("Wallet access cancelled");
            grant();
        }
        return s;
    }
    auto wallet = std::make_unique<Wallet>(filename(name));
    bool exists = std::filesystem::exists(wallet->path());
    if (exists) {
        auto header = read_private(wallet->path());
        if (header.size() > 16 && header[14] == 2) {
            if (!pinentry("Wallet access", requester + "\nRequests access to OpenPGP wallet “" + name + "”.", true))
                throw Error("Wallet access cancelled");
            wallet->open("");
            grant();
            s.wallet = std::move(wallet);
            if (changed)
                changed(name, "opened");
            return s;
        }
    }
    if (!exists && !pinentry("Create wallet", requester + "\nRequests creation of encrypted wallet “" + name + "”.", true))
        throw Error("Wallet creation cancelled");
    for (int attempts = 0; attempts < 3; attempts++) {
        auto secret = pinentry(exists ? "Unlock wallet" : "Create wallet",
            (attempts ? "The previous password did not unlock the wallet.\n" : "") + requester + "\nRequests wallet “" + name
                + "”.",
            false, !exists);
        if (!secret)
            throw Error("Wallet prompt cancelled");
        std::string password = utf8(*secret);
        try {
            if (exists)
                wallet->open(password);
            else
                wallet->create(password);
            explicit_bzero(password.data(), password.size());
            grant();
            s.wallet = std::move(wallet);
            if (changed)
                changed(name, exists ? "opened" : "created");
            return s;
        } catch (...) {
            explicit_bzero(password.data(), password.size());
            if (!exists || attempts == 2)
                throw;
        }
    }
    throw Error("Cannot unlock wallet");
}
int Backend::open(const std::string& name, const std::string& owner, const std::string& app)
{
    unlock(name, owner, app);
    if (next_handle == INT32_MAX)
        throw Error("Wallet handle limit reached");
    int h = next_handle++;
    handles.emplace(h, Handle { name, owner, app });
    return h;
}
State& Backend::access(int handle, const std::string& owner, const std::string& app)
{
    if (!enabled())
        throw Error("KWallet is disabled in configuration");
    auto it = handles.find(handle);
    if (it == handles.end() || it->second.owner != owner || it->second.app != app)
        throw Error("Invalid wallet handle or caller");
    auto& s = state(it->second.wallet);
    if (!s.wallet)
        throw Error("Wallet is locked");
    if (!authorized(s.name, owner))
        throw Error("Wallet caller process approval expired");
    s.last_access = std::chrono::steady_clock::now();
    return s;
}
void Backend::close(int handle, const std::string& owner, const std::string& app)
{
    access(handle, owner, app);
    handles.erase(handle);
}
void Backend::lock(const std::string& name)
{
    auto& s = state(name);
    s.wallet.reset();
    s.owners.clear();
    s.processes.clear();
    for (auto it = handles.begin(); it != handles.end();) {
        if (it->second.wallet == name)
            it = handles.erase(it);
        else
            ++it;
    }
    if (changed)
        changed(name, "closed");
}
void Backend::disconnect(const std::string& owner)
{
    for (auto& [name, s] : states)
        s.owners.erase(owner);
    for (auto it = handles.begin(); it != handles.end();) {
        if (it->second.owner == owner)
            it = handles.erase(it);
        else
            ++it;
    }
}
void Backend::save_metadata(State& s)
{
    s.metadata["$fdo_modified"] = std::to_string(time(nullptr));
    auto text = s.metadata.dump(2);
    atomic_write(root / (encode_name(s.name) + "_attributes.json"),
        std::span(reinterpret_cast<const unsigned char*>(text.data()), text.size()));
}
void Backend::save(State& s)
{
    if (!s.wallet)
        throw Error("Wallet is locked");
    s.wallet->save();
    if (changed)
        changed(s.name, "updated");
}
void Backend::erase(const std::string& name)
{
    auto p = filename(name);
    if (!std::filesystem::exists(p))
        throw Error("Wallet does not exist");
    if (!pinentry("Delete wallet", "Permanently delete encrypted wallet “" + name + "” and all of its entries?", true))
        throw Error("Wallet deletion cancelled");
    lock(name);
    for (auto path : { p, root / (encode_name(name) + ".salt"), root / (encode_name(name) + "_attributes.json") }) {
        if (std::filesystem::is_symlink(path))
            throw Error("Unsafe wallet path");
        std::filesystem::remove(path);
    }
    states.erase(name);
    if (changed)
        changed(name, "deleted");
}
void Backend::password(const std::string& name, const std::string& owner, const std::string& app)
{
    auto& s = unlock(name, owner, app);
    auto value = pinentry("Change wallet password", "Enter a new password for wallet “" + name + "”.", false, true);
    if (!value)
        throw Error("Password change cancelled");
    std::string text = utf8(*value);
    try {
        s.wallet->change_password(text);
        explicit_bzero(text.data(), text.size());
    } catch (...) {
        explicit_bzero(text.data(), text.size());
        throw;
    }
}
}

//
//  TailscaleManager.hpp
//  Moonlight-Switch
//
//  Bridge between the app and libtsnet: lifecycle, settings persistence
//  (<working dir>/tailscale/settings.json) and UI-thread event marshalling.
//
#pragma once

#include <Singleton.hpp>
#include <borealis/core/event.hpp>
#include <atomic>
#include <functional>
#include <string>
#include <vector>

struct TailscalePeer {
    std::string name;
    std::string ip4;
    bool online = false;
    bool sessionUp = false;
    std::string path; // "direct <ip:port>" or "derp-N"
};

class TailscaleManager : public Singleton<TailscaleManager> {
  public:
    // load settings; call once after Settings::set_working_dir
    void init();

    // True if init() will auto-start Tailscale for this working dir. Usable
    // before borealis is initialised (reads the settings file directly).
    static bool willAutoStart(const std::string& workingDir);

    // persisted settings
    [[nodiscard]] bool enabled() const { return m_enabled; }
    void setEnabled(bool enabled);
    [[nodiscard]] std::string serverUrl() const { return m_server_url; }
    void setServerUrl(const std::string& url);

    // authKey is only used for registration and never kept afterwards
    void start(const std::string& authKey = "");

    void stop();
    // App-teardown stop: like stop(), but first marks shuttingDown() so the
    // tsnet callbacks stop posting to the UI that is being destroyed.
    void shutdown();
    // stop and wipe keys and state
    void logout();
    [[nodiscard]] bool running() const { return m_running; }
    // true if node keys from a previous login exist on disk
    [[nodiscard]] bool isLoggedIn() const;

    // live state for the UI
    std::string stateString();
    std::string selfIp();
    std::vector<TailscalePeer> peers();

    // UI callbacks (invoked on the borealis main thread via brls::sync)
    std::function<void(const std::string& url)> onAuthUrl;
    std::function<void()> onStateChanged;
    // Fired on the UI thread each time the data plane comes up, so
    // views that probe tailnet hosts can retry without user interaction.
    brls::Event<>* getTunnelUpEvent() { return &m_tunnelUpEvent; }
    [[nodiscard]] bool tunnelUp() const { return m_tunnelUp; }

    [[nodiscard]] std::string stateDir() const { return m_state_dir; }

    // internal event sinks (invoked from tsnet callbacks on the UI thread)
    void _stateEvent(const std::string& detail);
    void _peersEvent();

    // tsnet callbacks run on worker threads and post to the UI via
    // brls::sync; once shutdown() starts they become no-ops so no task runs
    // against the view tree borealis is destroying.
    [[nodiscard]] bool shuttingDown() const { return m_shuttingDown; }

  private:
    void load();
    void save();

    bool m_enabled = false;
    std::string m_server_url = "https://controlplane.tailscale.com";
    std::string m_hostname = "moonlight-switch";
    std::string m_state_dir;
    std::string m_settings_path;
    std::string m_crash_flag; // present while a start has not reached RUNNING
    bool m_running = false;
    std::atomic<bool> m_shuttingDown{false};
    std::string m_state_detail;
    bool m_tunnelUp = false;
    brls::Event<> m_tunnelUpEvent;
};

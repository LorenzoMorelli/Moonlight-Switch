//
//  tailscale_tab.cpp
//  Moonlight-Switch
//
#include "tailscale_tab.hpp"

#include "Settings.hpp"
#include "TailscaleManager.hpp"

#include <fmt/core.h>

using namespace brls::literals;

TailscaleTab::TailscaleTab() {
    this->inflateFromXMLRes("xml/tabs/tailscale.xml");
    auto& ts = TailscaleManager::instance();

    enabled->init("tailscale/enabled"_i18n, ts.enabled(), [this](bool value) {
        auto& mgr = TailscaleManager::instance();
        if (value && !mgr.isLoggedIn()) {
            // nothing to reconnect with: ask the user to log in first
            auto* dlg = new brls::Dialog("tailscale/not_logged_in"_i18n);
            dlg->addButton("common/close"_i18n, [] {});
            dlg->open();
            this->enabled->setOn(false, false);
            return;
        }
        mgr.setEnabled(value);
    });

    serverUrl->init("tailscale/server_url"_i18n, ts.serverUrl(),
                    [](const std::string& value) {
                        TailscaleManager::instance().setServerUrl(value);
                    },
                    "https://controlplane.tailscale.com", "", 256);

    loginKey->setText("tailscale/login_key"_i18n);
    loginKey->setDetailText("");
    loginKey->registerClickAction([this](brls::View*) {
        promptAuthKey();
        return true;
    });

    loginUrl->setText("tailscale/login_url"_i18n);
    loginUrl->setDetailText("");
    loginUrl->registerClickAction([this](brls::View*) {
        auto& mgr = TailscaleManager::instance();
        // interactive login: the AuthURL arrives later via onAuthUrl
        if (!mgr.running()) mgr.start();
        showLoginSpinner();
        return true;
    });

    logout->setText("tailscale/logout"_i18n);
    logout->setDetailText("");
    logout->registerClickAction([this](brls::View*) {
        auto* dialog = new brls::Dialog("tailscale/logout_confirm"_i18n);
        dialog->addButton("common/cancel"_i18n, [] {});
        dialog->addButton("tailscale/logout"_i18n, [this] {
            TailscaleManager::instance().logout();
            this->refresh();
        });
        dialog->open();
        return true;
    });

    ts.onAuthUrl = [this](const std::string& url) {
        this->dismissLoginSpinner();
        auto* dialog = new brls::Dialog(
            fmt::format(fmt::runtime("tailscale/authurl_dialog"_i18n), url));
        dialog->addButton("common/close"_i18n, [] {});
        dialog->open();
    };
    ts.onStateChanged = [this] { this->refresh(); };

    refresh();
}

TailscaleTab::~TailscaleTab() {
    auto& ts = TailscaleManager::instance();
    ts.onAuthUrl = nullptr;
    ts.onStateChanged = nullptr;
    dismissLoginSpinner();
}

void TailscaleTab::showLoginSpinner() {
    if (loginSpinner) return;
    auto* content = new brls::Box(brls::Axis::COLUMN);
    content->setJustifyContent(brls::JustifyContent::CENTER);
    content->setAlignItems(brls::AlignItems::CENTER);
    content->setPadding(50);
    auto* spinner = new brls::ProgressSpinner();
    spinner->setWidth(70);
    spinner->setHeight(70);
    content->addView(spinner);
    auto* label = new brls::Label();
    label->setText("tailscale/login_url_generating"_i18n);
    label->setMarginTop(24);
    content->addView(label);

    loginSpinner = new brls::Dialog(content);
    // cancelling only hides the wait; the URL dialog still appears later
    loginSpinner->addButton("common/cancel"_i18n, [this] {
        loginSpinner = nullptr; // dialog closes itself after the callback
    });
    loginSpinner->open();
}

void TailscaleTab::dismissLoginSpinner() {
    if (!loginSpinner) return;
    loginSpinner->close();
    loginSpinner = nullptr;
}

void TailscaleTab::promptAuthKey() {
    brls::Application::getImeManager()->openForText(
        [](const std::string& text) {
            if (text.empty()) return;
            auto& mgr = TailscaleManager::instance();
            if (mgr.running()) mgr.stop();
            mgr.start(text);
            mgr.setEnabled(true); // already running: only persists the flag
        },
        "tailscale/login_key"_i18n, "tskey-auth-...", 256, "", 0);
}

void TailscaleTab::refresh() {
    auto& ts = TailscaleManager::instance();
    statusHeader->setSubtitle(ts.stateString());

    auto peers = ts.peers();
    // Rebuild the peer cells only when the list changed: refresh() runs on
    // every state tick, and freeing a cell that is focused or mid-tap
    // crashes the gesture recognizer.
    std::string sig;
    for (auto& p : peers)
        sig += p.name + "|" + p.ip4 + "|" + p.path + "|" +
               (p.online ? "1" : "0") + (p.sessionUp ? "1" : "0") + ";";
    if (sig != lastPeersSig) {
        lastPeersSig = sig;
        peersBox->clearViews();
        for (auto& p : peers) {
            auto* cell = new brls::DetailCell();
            cell->setText(p.name);
            std::string detail = p.ip4;
            if (p.sessionUp) detail += "  [" + p.path + "]";
            if (!p.online) detail += "  (offline)";
            cell->setDetailText(detail);
            std::string ip = p.ip4;
            cell->registerClickAction([ip](brls::View*) {
                brls::Application::notify(fmt::format(
                    fmt::runtime("tailscale/add_host_hint"_i18n), ip));
                return true;
            });
            peersBox->addView(cell);
        }
        peersHeader->setSubtitle(fmt::format("{}", peers.size()));
    }

    std::string diag = fmt::format("state: {}\nself: {}\npeers: {}",
                                   ts.stateString(), ts.selfIp(),
                                   peers.size());
    for (auto& p : peers)
        diag += fmt::format("\n  {} {} online={} session={} path={}", p.name,
                            p.ip4, p.online, p.sessionUp, p.path);
    diagLabel->setText(diag);
}

brls::View* TailscaleTab::create() { return new TailscaleTab(); }

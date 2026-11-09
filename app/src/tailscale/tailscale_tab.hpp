//
//  tailscale_tab.hpp
//  Moonlight-Switch
//
#pragma once

#include <borealis.hpp>
#include <string>

class TailscaleTab : public brls::Box {
  public:
    TailscaleTab();
    ~TailscaleTab() override;

    static brls::View* create();

  private:
    void refresh();
    void promptAuthKey();
    void showLoginSpinner();
    void dismissLoginSpinner();

    brls::Dialog* loginSpinner = nullptr;
    std::string lastPeersSig;

    BRLS_BIND(brls::Header, statusHeader, "status_header");
    BRLS_BIND(brls::BooleanCell, enabled, "enabled");
    BRLS_BIND(brls::InputCell, serverUrl, "server_url");
    BRLS_BIND(brls::DetailCell, loginKey, "login_key");
    BRLS_BIND(brls::DetailCell, loginUrl, "login_url");
    BRLS_BIND(brls::DetailCell, logout, "logout");
    BRLS_BIND(brls::Header, peersHeader, "peers_header");
    BRLS_BIND(brls::Box, peersBox, "peers_box");
    BRLS_BIND(brls::Label, diagLabel, "diag_label");
};

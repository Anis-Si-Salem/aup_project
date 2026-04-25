#include <gtk/gtk.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <cstring>
#include <unistd.h>

#include <openssl/crypto.h>

#include "fingerprint.h"
#include "verifier.h"
#include "app_loader.h"
#include "anti_re.h"
#include "license_embed.h"
#include "tpm_attest.h"
#include "tpm_seal.h"
#include "secure_logger.h"

static std::string g_fp_hash;
static std::string g_license_path;
static std::string g_pubkey_path;
static std::string g_license_json;
static std::string g_pubkey_pem;
static verifier::license_data g_lic;
static bool g_verified = false;

static void on_pubkey_response(GObject* source, GAsyncResult* res, gpointer user_data);

static std::string read_file_str(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string get_exe_dir() {
    char exe[4096] = {};
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len <= 0) return "./";
    exe[len] = '\0';
    std::string dir(exe);
    auto slash = dir.rfind('/');
    return (slash != std::string::npos) ? dir.substr(0, slash + 1) : "./";
}

static void on_copy_fp(GtkButton* btn, gpointer user_data) {
    GdkDisplay* display = gdk_display_get_default();
    GdkClipboard* clip = gdk_display_get_clipboard(display);
    gdk_clipboard_set_text(clip, g_fp_hash.c_str());
    gtk_button_set_label(btn, "Copied!");
}

static void on_license_response(GObject* source, GAsyncResult* res, gpointer user_data) {
    GtkButton* btn = GTK_BUTTON(user_data);
    GtkFileChooser* chooser = GTK_FILE_CHOOSER(source);
    GFile* file = gtk_file_dialog_open_finish(GTK_FILE_DIALOG(g_object_ref(source)), res, nullptr);
    if (file) {
        char* path = g_file_get_path(file);
        g_license_path = path;
        gtk_button_set_label(btn, path);
        g_free(path);
        g_object_unref(file);
    }
}

static void on_pubkey_response(GObject* source, GAsyncResult* res, gpointer user_data) {
    GtkButton* btn = GTK_BUTTON(user_data);
    GFile* file = gtk_file_dialog_open_finish(GTK_FILE_DIALOG(g_object_ref(source)), res, nullptr);
    if (file) {
        char* path = g_file_get_path(file);
        g_pubkey_path = path;
        gtk_button_set_label(btn, path);
        g_free(path);
        g_object_unref(file);
    }
}

static void on_license_chooser(GtkButton* btn, gpointer user_data) {
    GtkWindow* parent = GTK_WINDOW(user_data);
    GtkFileDialog* dialog = gtk_file_dialog_new();
    gtk_file_dialog_set_title(dialog, "Select License File");

    GtkFileFilter* filter = gtk_file_filter_new();
    gtk_file_filter_set_name(filter, "License Files");
    gtk_file_filter_add_pattern(filter, "*.json");
    GListStore* filters = g_list_store_new(GTK_TYPE_FILE_FILTER);
    g_list_store_append(filters, filter);
    gtk_file_dialog_set_filters(dialog, G_LIST_MODEL(filters));
    g_object_unref(filters);

    gtk_file_dialog_open(dialog, parent, nullptr, on_license_response, btn);
    g_object_unref(dialog);
}

static void on_pubkey_chooser(GtkButton* btn, gpointer user_data) {
    GtkWindow* parent = GTK_WINDOW(user_data);
    GtkFileDialog* dialog = gtk_file_dialog_new();
    gtk_file_dialog_set_title(dialog, "Select Public Key");

    GtkFileFilter* filter = gtk_file_filter_new();
    gtk_file_filter_set_name(filter, "PEM Files");
    gtk_file_filter_add_pattern(filter, "*.pem");
    GListStore* filters2 = g_list_store_new(GTK_TYPE_FILE_FILTER);
    g_list_store_append(filters2, filter);
    gtk_file_dialog_set_filters(dialog, G_LIST_MODEL(filters2));
    g_object_unref(filters2);

    gtk_file_dialog_open(dialog, parent, nullptr, on_pubkey_response, btn);
    g_object_unref(dialog);
}

static void on_verify(GtkButton* btn, gpointer user_data) {
    GtkLabel* status = GTK_LABEL(user_data);
    g_verified = false;

    if (g_license_path.empty() || g_pubkey_path.empty()) {
        gtk_label_set_text(status, "Please select both license and public key files.");
        return;
    }

    g_license_json = read_file_str(g_license_path);
    g_pubkey_pem = read_file_str(g_pubkey_path);

    if (g_license_json.empty()) { gtk_label_set_text(status, "Cannot read license file."); return; }
    if (g_pubkey_pem.empty()) { gtk_label_set_text(status, "Cannot read public key file."); return; }

    if (!verifier::verify_license(g_license_json, g_pubkey_pem, g_lic)) {
        gtk_label_set_text(status, "INVALID LICENSE\nSignature verification failed.");
        return;
    }

    if (g_lic.fingerprint != g_fp_hash) {
        if (tpm_attest::tpm_available()) {
            gtk_label_set_text(status, "FINGERPRINT MISMATCH\nHardware changed (TPM detected) - possible disk cloning.");
        } else {
            gtk_label_set_text(status, "FINGERPRINT MISMATCH\nLicense is for a different machine.");
        }
        return;
    }

    if (verifier::is_expired(g_lic)) {
        gtk_label_set_text(status, "License EXPIRED.");
        return;
    }

    g_verified = true;
    int days = verifier::days_remaining(g_lic);
    gchar* msg = g_strdup_printf(
        "License verified!\nMax Users: %d | Expires in: %d days\nFingerprint matches.",
        g_lic.max_users, days);
    gtk_label_set_text(status, msg);
    g_free(msg);
}

static void on_install(GtkButton* btn, gpointer user_data) {
    GtkLabel* status = GTK_LABEL(user_data);

    if (!g_verified) {
        gtk_label_set_text(status, "Please verify the license first.");
        return;
    }

    char exe_path[4096] = {};
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len <= 0) { gtk_label_set_text(status, "Cannot determine executable path."); return; }
    exe_path[len] = '\0';

    std::string install_dir = "/usr/local/bin";
    std::string install_path = install_dir + "/secure_app";
    std::string exe_dir = get_exe_dir();

    std::string vendor_key_path = exe_dir + "app_core.key";
    uint8_t vendor_key[32] = {};
    bool has_vendor_key = false;
    {
        std::ifstream vkf(vendor_key_path, std::ios::binary);
        if (vkf.is_open() && vkf.read(reinterpret_cast<char*>(vendor_key), 32)) {
            has_vendor_key = true;
        }
    }

    license_embed::embedded_license lic_data = {};
    memcpy(lic_data.magic, "SECURELIC01", 11);
    lic_data.version = 1;
    lic_data.expiry_timestamp = g_lic.expiry_timestamp;
    strncpy(lic_data.fp_hash, g_fp_hash.c_str(), sizeof(lic_data.fp_hash) - 1);

    {
        std::string signature_b64 = verifier::extract_signature(g_license_json);
        auto sig_bytes = verifier::b64_decode_raw(signature_b64);
        if (sig_bytes.size() == 64) {
            memcpy(lic_data.ed25519_signature, sig_bytes.data(), 64);
        }
    }

    {
        std::string canonical_json = verifier::strip_signature(g_license_json);
        strncpy(lic_data.payload, canonical_json.c_str(),
                std::min(canonical_json.size(), sizeof(lic_data.payload) - 1));
        lic_data.canonical_json_len = static_cast<uint16_t>(
            std::min(canonical_json.size(), sizeof(lic_data.payload) - 1));
    }

    std::string enc_dst_path = install_dir + "/app_core.enc";
    std::string tss_key_path = install_dir + "/app_core.enc.key.tss";
    uint8_t machine_key[32] = {};

    if (has_vendor_key) {
        std::string enc_src_path = exe_dir + "app_core.enc";
        std::string reenc_tmp = "/tmp/secure_app_gui_reenc_" + std::to_string(getpid()) + ".enc";

        if (app_loader::re_encrypt_payload(enc_src_path, vendor_key, machine_key, reenc_tmp)) {
            std::ifstream src(reenc_tmp, std::ios::binary);
            if (src.is_open()) {
                std::ofstream dst(enc_dst_path, std::ios::binary);
                dst << src.rdbuf();
            }
            unlink(reenc_tmp.c_str());

            if (tpm_attest::tpm_available()) {
                std::vector<uint8_t> key_vec(machine_key, machine_key + 32);
                auto seal_result = tpm_seal::seal_license_key(key_vec);
                if (seal_result.success) {
                    std::ofstream kf(tss_key_path, std::ios::binary);
                    kf.write(reinterpret_cast<const char*>(seal_result.sealed_data.data()),
                             seal_result.sealed_data.size());
                } else {
                    std::string fallback = install_dir + "/app_core.enc.key.bin";
                    std::ofstream kf(fallback, std::ios::binary);
                    kf.write(reinterpret_cast<const char*>(machine_key), 32);
                }
            } else {
                std::string fallback = install_dir + "/app_core.enc.key.bin";
                std::ofstream kf(fallback, std::ios::binary);
                kf.write(reinterpret_cast<const char*>(machine_key), 32);
            }
        }
        OPENSSL_cleanse(vendor_key, sizeof(vendor_key));
        OPENSSL_cleanse(machine_key, sizeof(machine_key));
    } else {
        std::ifstream src(exe_dir + "app_core.enc", std::ios::binary);
        if (src.is_open()) {
            std::ofstream dst(enc_dst_path, std::ios::binary);
            dst << src.rdbuf();
        }
    }

    if (!license_embed::patch_binary(exe_path, install_path, lic_data)) {
        install_path = "./secure_app_installed";
        if (!license_embed::patch_binary(exe_path, install_path, lic_data)) {
            gtk_label_set_text(status, "Installation failed.");
            return;
        }
    }

    secure_logger::init(std::string(lic_data.fp_hash));
    secure_logger::log_license("install_gui", true);

    gchar* msg = g_strdup_printf("Installed to %s\nRun it to start the application.", install_path.c_str());
    gtk_label_set_text(status, msg);
    g_free(msg);
}

static void on_close(GtkWidget* widget, gpointer data) {
    anti_re::stop_background_monitor();
    secure_logger::shutdown();
    gtk_window_close(GTK_WINDOW(widget));
}

int main(int argc, char* argv[]) {
    anti_re::init();
    anti_re::start_background_monitor();

    GtkApplication* app = gtk_application_new("com.secure.installer", G_APPLICATION_DEFAULT_FLAGS);

    g_signal_connect(app, "activate", G_CALLBACK(+[](GtkApplication* app, gpointer) {
        GtkWidget* window = gtk_application_window_new(app);
        gtk_window_set_title(GTK_WINDOW(window), "On-Premise Security Installer");
        gtk_window_set_default_size(GTK_WINDOW(window), 600, 560);
        g_signal_connect(window, "close-request", G_CALLBACK(on_close), nullptr);

        GtkWidget* vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
        gtk_widget_set_margin_start(vbox, 20);
        gtk_widget_set_margin_end(vbox, 20);
        gtk_widget_set_margin_top(vbox, 20);
        gtk_widget_set_margin_bottom(vbox, 20);
        gtk_window_set_child(GTK_WINDOW(window), vbox);

        GtkWidget* title = gtk_label_new(NULL);
        gtk_label_set_markup(GTK_LABEL(title), "<span font_desc='16' weight='bold'>On-Premise Security Installer</span>");
        gtk_box_append(GTK_BOX(vbox), title);

        // Step 1: Fingerprint
        GtkWidget* frame1 = gtk_frame_new("Step 1: Hardware Fingerprint");
        gtk_box_append(GTK_BOX(vbox), frame1);
        GtkWidget* box1 = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
        gtk_widget_set_margin_start(box1, 10);
        gtk_widget_set_margin_end(box1, 10);
        gtk_widget_set_margin_top(box1, 10);
        gtk_widget_set_margin_bottom(box1, 10);
        gtk_frame_set_child(GTK_FRAME(frame1), box1);

        fingerprint::hardware_ids hw = fingerprint::collect_all();
        g_fp_hash = fingerprint::compute_hash(hw);

        if (!hw.tpm_available) {
            GtkWidget* err_label = gtk_label_new("ERROR: TPM is REQUIRED.\nThis machine has no TPM.\nCannot proceed.");
            gtk_label_set_use_markup(GTK_LABEL(err_label), TRUE);
            gtk_label_set_markup(GTK_LABEL(err_label), "<span foreground='red' weight='bold'>ERROR: TPM is REQUIRED</span>\nThis machine has no TPM.");
            gtk_box_append(GTK_BOX(box1), err_label);
            return;
        }

        std::string fp_detail;
        if (hw.tpm_available) fp_detail += "TPM: Required";
        if (!hw.tpm_ek_hash.empty()) fp_detail += "\nTPM EK: " + hw.tpm_ek_hash.substr(0, 16) + "...";
        if (!hw.machine_id.empty()) fp_detail += "\nMachine: " + hw.machine_id.substr(0, 12) + "...";

        GtkWidget* fp_label = gtk_label_new(g_fp_hash.c_str());
        gtk_label_set_selectable(GTK_LABEL(fp_label), TRUE);
        gtk_box_append(GTK_BOX(box1), fp_label);

        GtkWidget* copy_btn = gtk_button_new_with_label("Copy to Clipboard");
        g_signal_connect(copy_btn, "clicked", G_CALLBACK(on_copy_fp), nullptr);
        gtk_box_append(GTK_BOX(box1), copy_btn);

        if (!fp_detail.empty()) {
            GtkWidget* detail_lbl = gtk_label_new(fp_detail.c_str());
            gtk_box_append(GTK_BOX(box1), detail_lbl);
        }

        // Step 2: File Selection
        GtkWidget* frame2 = gtk_frame_new("Step 2: Provide License Files");
        gtk_box_append(GTK_BOX(vbox), frame2);
        GtkWidget* box2 = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
        gtk_widget_set_margin_start(box2, 10);
        gtk_widget_set_margin_end(box2, 10);
        gtk_widget_set_margin_top(box2, 10);
        gtk_widget_set_margin_bottom(box2, 10);
        gtk_frame_set_child(GTK_FRAME(frame2), box2);

        GtkWidget* lic_btn = gtk_button_new_with_label("Select license.json...");
        g_signal_connect(lic_btn, "clicked", G_CALLBACK(on_license_chooser), window);
        gtk_box_append(GTK_BOX(box2), lic_btn);

        GtkWidget* key_btn = gtk_button_new_with_label("Select pubkey.pem...");
        g_signal_connect(key_btn, "clicked", G_CALLBACK(on_pubkey_chooser), window);
        gtk_box_append(GTK_BOX(box2), key_btn);

        // Step 3: Verify
        GtkWidget* frame3 = gtk_frame_new("Step 3: License Verification");
        gtk_box_append(GTK_BOX(vbox), frame3);
        GtkWidget* box3 = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
        gtk_widget_set_margin_start(box3, 10);
        gtk_widget_set_margin_end(box3, 10);
        gtk_widget_set_margin_top(box3, 10);
        gtk_widget_set_margin_bottom(box3, 10);
        gtk_frame_set_child(GTK_FRAME(frame3), box3);

        GtkWidget* status_label = gtk_label_new("Select files above, then click Verify.");
        gtk_label_set_wrap(GTK_LABEL(status_label), TRUE);
        gtk_box_append(GTK_BOX(box3), status_label);

        GtkWidget* verify_btn = gtk_button_new_with_label("Verify License");
        g_signal_connect(verify_btn, "clicked", G_CALLBACK(on_verify), status_label);
        gtk_box_append(GTK_BOX(box3), verify_btn);

        // Step 4: Install
        GtkWidget* frame4 = gtk_frame_new("Step 4: Install");
        gtk_box_append(GTK_BOX(vbox), frame4);
        GtkWidget* box4 = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
        gtk_widget_set_margin_start(box4, 10);
        gtk_widget_set_margin_end(box4, 10);
        gtk_widget_set_margin_top(box4, 10);
        gtk_widget_set_margin_bottom(box4, 10);
        gtk_frame_set_child(GTK_FRAME(frame4), box4);

        GtkWidget* install_status = gtk_label_new("Verify the license before installing.");
        gtk_label_set_wrap(GTK_LABEL(install_status), TRUE);
        gtk_box_append(GTK_BOX(box4), install_status);

        GtkWidget* install_btn = gtk_button_new_with_label("Install Application");
        g_signal_connect(install_btn, "clicked", G_CALLBACK(on_install), install_status);
        gtk_box_append(GTK_BOX(box4), install_btn);

        gtk_window_present(GTK_WINDOW(window));
    }), nullptr);

    int rc = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return rc;
}
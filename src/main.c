/*
 * main.c — PQ-Sealed GTK3 GUI.
 *
 * A front-end over the backup engine in repo.c. Each operation (initialise,
 * back up, restore, list, verify) runs on a worker thread so the Argon2id KDF
 * and large file walks never freeze the UI; the engine streams progress lines
 * back through a log callback that is marshalled onto the GTK main loop.
 */
#include <gtk/gtk.h>
#include <string.h>
#include <sodium.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#include "sealed.h"

#define APP_ID       "org.effjy.PQSealed"
#define PASSWORD_MAX 1024

/* Cyber-styled dark theme, matching the wider tool-set (Ciphers et al.). */
static const char *APP_CSS =
    "window, .root { background-color: #070b12; color: #c8f7ff; }"
    "headerbar, .titlebar {"
    "  background: linear-gradient(90deg, #0a0f1a, #0e1726, #0a0f1a);"
    "  border-bottom: 1px solid #00e5ff;"
    "  box-shadow: 0 1px 8px rgba(0,229,255,0.35); min-height: 40px; }"
    ".hb-title { color: #00e5ff; font-family: monospace; font-weight: bold;"
    "  letter-spacing: 2px; }"
    "headerbar button { padding: 2px 10px; margin: 4px 2px; min-height: 0;"
    "  min-width: 0; }"
    "headerbar button.titlebutton { padding: 2px; margin: 2px;"
    "  min-height: 22px; min-width: 22px; }"
    "label { color: #9fd6e6; font-family: monospace; }"
    ".field-label { color: #5fb4c9; letter-spacing: 1px; }"
    ".brand { color: #00e5ff; font-family: monospace; font-weight: bold;"
    "  font-size: 20px; letter-spacing: 5px; }"
    ".subtitle { color: #3d7d8f; font-size: 10px; letter-spacing: 3px; }"
    "entry { background-color: #0c1421; color: #d8feff; border: 1px solid #14384a;"
    "  border-radius: 4px; padding: 3px 7px; min-height: 0; font-family: monospace;"
    "  caret-color: #00e5ff; }"
    "entry:focus { border-color: #00e5ff; box-shadow: 0 0 6px rgba(0,229,255,0.6); }"
    "combobox box, combobox button, combobox { background-color: #0c1421;"
    "  color: #d8feff; border: 1px solid #14384a; border-radius: 4px;"
    "  min-height: 0; padding: 0 4px; font-family: monospace; }"
    "combobox button:hover { border-color: #00e5ff; }"
    "checkbutton { color: #9fd6e6; font-family: monospace; }"
    "checkbutton check { background-color: #0c1421; border: 1px solid #2a6b80; }"
    "checkbutton check:checked { background-color: #00e5ff; border-color: #00e5ff; }"
    "button { background: #0e1b2b; color: #9fe9ff; border: 1px solid #1d4c5e;"
    "  border-radius: 4px; padding: 3px 12px; min-height: 0; font-family: monospace;"
    "  letter-spacing: 1px; }"
    "button:hover { border-color: #00e5ff; color: #ffffff;"
    "  box-shadow: 0 0 8px rgba(0,229,255,0.45); }"
    "button:disabled { color: #3a566a; border-color: #16313e; }"
    ".action-button { background: linear-gradient(90deg, #00b3c4, #00e5ff);"
    "  color: #000000; font-weight: bold; letter-spacing: 2px;"
    "  border: 1px solid #00e5ff; }"
    ".action-button label { color: #000000; }"
    ".action-button:hover label { color: #000000; }"
    ".action-button:hover { box-shadow: 0 0 14px rgba(0,229,255,0.8); color: #000; }"
    "progressbar trough { background-color: #0c1421; border: 1px solid #14384a;"
    "  border-radius: 4px; min-height: 14px; }"
    "progressbar progress { background: linear-gradient(90deg, #00b3c4, #39ff14);"
    "  border-radius: 4px; min-height: 14px; box-shadow: 0 0 10px rgba(57,255,20,0.6); }"
    "textview, textview text { background-color: #060a10; color: #9fe9ff;"
    "  font-family: monospace; font-size: 11px; }"
    ".status-ok { color: #39ff14; } .status-err { color: #ff426f; }"
    ".status-run { color: #00e5ff; }";

enum { OP_INIT = 0, OP_BACKUP, OP_RESTORE, OP_LIST, OP_VERIFY, OP_DELETE };

typedef struct Job Job;

typedef struct {
    GtkApplication *gapp;
    GtkWidget *window;
    GtkWidget *repo_entry;
    GtkWidget *op_combo;
    GtkWidget *path_label;     /* the field-label for path_entry */
    GtkWidget *path_entry;     /* source (backup) / destination (restore) */
    GtkWidget *path_btn;
    GtkWidget *snap_label;
    GtkWidget *snap_entry;     /* snapshot name (restore) */
    GtkWidget *repo_pw_entry;
    GtkWidget *repo_pw_confirm; /* re-enter backup password (init only) */
    GtkWidget *repo_confirm_row;
    GtkWidget *key_pw_label;
    GtkWidget *key_pw_entry;   /* signing passphrase (init/backup) */
    GtkWidget *key_pw_confirm;  /* re-enter signing passphrase (init only) */
    GtkWidget *key_confirm_row;
    GtkWidget *run_button;
    GtkWidget *progress;
    GtkWidget *status;
    GtkTextBuffer *logbuf;
    guint      pulse_id;
    gboolean   pulsing;
    volatile int cancel;
    volatile int window_gone;
    Job * volatile current_job;
} App;

struct Job {
    App *app;
    int  op;
    char repo[4096];
    char path2[4096];      /* source dir or restore destination */
    char snapshot[256];
    char repo_pw[PASSWORD_MAX];
    char key_pw[PASSWORD_MAX];
    int  rc;
    char err[256];
};

/* ----- log marshalling (worker thread -> main loop) --------------------- */

typedef struct { App *app; char *text; } LogMsg;

static gboolean append_log_idle(gpointer data) {
    LogMsg *m = data;
    if (!m->app->window_gone) {
        GtkTextIter end;
        gtk_text_buffer_get_end_iter(m->app->logbuf, &end);
        gtk_text_buffer_insert(m->app->logbuf, &end, m->text, -1);
        gtk_text_buffer_insert(m->app->logbuf, &end, "\n", 1);
        /* Auto-scroll to the bottom. */
        GtkTextMark *mk = gtk_text_buffer_get_insert(m->app->logbuf);
        gtk_text_buffer_move_mark(m->app->logbuf, mk, &end);
    }
    g_free(m->text);
    g_free(m);
    return G_SOURCE_REMOVE;
}

/* Called from the worker thread. Returns non-zero to request cancellation. */
static int log_cb(const char *line, void *user) {
    App *app = user;
    LogMsg *m = g_new0(LogMsg, 1);
    m->app = app;
    m->text = g_strdup(line);
    g_idle_add(append_log_idle, m);
    return app->cancel;
}

/* ----- progress pulse --------------------------------------------------- */

static void stop_pulse(App *app) {
    app->pulsing = FALSE;
    if (app->pulse_id) { g_source_remove(app->pulse_id); app->pulse_id = 0; }
}
static gboolean pulse_cb(gpointer data) {
    App *app = data;
    if (!app->pulsing || app->window_gone) { app->pulse_id = 0; return G_SOURCE_REMOVE; }
    gtk_progress_bar_pulse(GTK_PROGRESS_BAR(app->progress));
    return G_SOURCE_CONTINUE;
}

static void set_status(App *app, const char *cls, const char *text) {
    GtkStyleContext *sc = gtk_widget_get_style_context(app->status);
    gtk_style_context_remove_class(sc, "status-ok");
    gtk_style_context_remove_class(sc, "status-err");
    gtk_style_context_remove_class(sc, "status-run");
    if (cls) gtk_style_context_add_class(sc, cls);
    gtk_label_set_text(GTK_LABEL(app->status), text);
}

static void free_app(App *app) { stop_pulse(app); g_free(app); }

/* ----- worker thread ---------------------------------------------------- */

static void refresh_snapshots(App *app);

static gboolean job_finished_idle(gpointer data) {
    Job *job = data;
    App *app = job->app;
    app->current_job = NULL;
    stop_pulse(app);

    if (app->window_gone) {
        sodium_munlock(job->repo_pw, sizeof job->repo_pw);
        sodium_munlock(job->key_pw, sizeof job->key_pw);
        g_free(job);
        g_application_release(G_APPLICATION(app->gapp));
        free_app(app);
        return G_SOURCE_REMOVE;
    }

    gtk_widget_set_sensitive(app->run_button, TRUE);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress),
                                  job->rc == 0 ? 1.0 : 0.0);
    if (job->rc == 0) {
        set_status(app, "status-ok", "\xE2\x9C\x94 Done.");
        /* Operations that add or remove a snapshot invalidate the drop-down. */
        if (job->op == OP_DELETE || job->op == OP_BACKUP)
            refresh_snapshots(app);
    } else {
        gchar *msg = g_strdup_printf("\xE2\x9C\x96 %s", job->err);
        set_status(app, "status-err", msg);
        GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(app->window),
            GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "%s", job->err);
        gtk_dialog_run(GTK_DIALOG(d));
        gtk_widget_destroy(d);
        g_free(msg);
    }

    sodium_munlock(job->repo_pw, sizeof job->repo_pw);
    sodium_munlock(job->key_pw, sizeof job->key_pw);
    g_free(job);
    g_application_release(G_APPLICATION(app->gapp));
    return G_SOURCE_REMOVE;
}

static gpointer worker_thread(gpointer data) {
    Job *job = data;
    App *app = job->app;
    switch (job->op) {
    case OP_INIT:
        job->rc = sealed_init(job->repo, job->repo_pw, job->key_pw,
                              job->err, sizeof job->err);
        break;
    case OP_BACKUP:
        job->rc = sealed_backup(job->repo, job->path2, job->repo_pw, job->key_pw,
                                log_cb, app, job->err, sizeof job->err);
        break;
    case OP_RESTORE:
        job->rc = sealed_restore(job->repo, job->snapshot, job->path2,
                                 job->repo_pw, log_cb, app, job->err, sizeof job->err);
        break;
    case OP_LIST:
        job->rc = sealed_list(job->repo, job->repo_pw, log_cb, app,
                              job->err, sizeof job->err);
        break;
    case OP_VERIFY:
        job->rc = sealed_verify(job->repo, NULL, log_cb, app,
                                job->err, sizeof job->err);
        break;
    case OP_DELETE:
        job->rc = sealed_delete(job->repo, job->snapshot, job->repo_pw,
                                log_cb, app, job->err, sizeof job->err);
        break;
    }
    g_idle_add(job_finished_idle, job);
    return NULL;
}

/* ----- UI callbacks ----------------------------------------------------- */

static void browse_folder(App *app, GtkWidget *entry) {
    GtkWidget *dlg = gtk_file_chooser_dialog_new("Select folder",
        GTK_WINDOW(app->window), GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
        "_Cancel", GTK_RESPONSE_CANCEL, "_Select", GTK_RESPONSE_ACCEPT, NULL);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        char *f = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        gtk_entry_set_text(GTK_ENTRY(entry), f);
        g_free(f);
    }
    gtk_widget_destroy(dlg);
}
static void on_browse_repo(GtkButton *b, gpointer u) {
    (void)b; App *a = u; browse_folder(a, a->repo_entry);
}
static void on_browse_path(GtkButton *b, gpointer u) {
    (void)b; App *a = u; browse_folder(a, a->path_entry);
}

static void reveal_toggled(GtkToggleButton *btn, gpointer u) {
    gtk_entry_set_visibility(GTK_ENTRY(u), gtk_toggle_button_get_active(btn));
}

/* Repopulate the snapshot drop-down from the currently chosen repository,
 * preserving the user's selection where possible. Restore offers "latest" as a
 * convenience; Delete does not — it forces an explicit, deliberate choice. */
static void refresh_snapshots(App *app) {
    GtkComboBoxText *c = GTK_COMBO_BOX_TEXT(app->snap_entry);
    gchar *prev = gtk_combo_box_text_get_active_text(c);
    int op = gtk_combo_box_get_active(GTK_COMBO_BOX(app->op_combo));

    gtk_combo_box_text_remove_all(c);
    if (op != OP_DELETE)
        gtk_combo_box_text_append_text(c, "latest");

    const char *repo = gtk_entry_get_text(GTK_ENTRY(app->repo_entry));
    size_t n = 0;
    char **names = (repo && *repo) ? sealed_snapshots(repo, &n) : NULL;
    /* Newest first is friendlier in a menu (sealed_snapshots is oldest-first). */
    for (size_t i = n; i-- > 0; ) {
        gtk_combo_box_text_append_text(c, names[i]);
        free(names[i]);
    }
    free(names);

    int active = 0;  /* default to "latest" */
    /* Re-select the previous choice if it still exists. */
    if (prev) {
        GtkTreeModel *m = gtk_combo_box_get_model(GTK_COMBO_BOX(c));
        GtkTreeIter it; int idx = 0; gboolean ok = gtk_tree_model_get_iter_first(m, &it);
        while (ok) {
            gchar *txt = NULL;
            gtk_tree_model_get(m, &it, 0, &txt, -1);
            if (txt && strcmp(txt, prev) == 0) { active = idx; g_free(txt); break; }
            g_free(txt);
            ok = gtk_tree_model_iter_next(m, &it); idx++;
        }
        g_free(prev);
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(c), active);
}

static void on_repo_changed(GtkEditable *e, gpointer user) {
    (void)e;
    refresh_snapshots((App *)user);
}

/* Enable/disable fields and relabel for the selected operation. */
static void on_op_changed(GtkComboBox *combo, gpointer user) {
    App *app = user;
    int op = gtk_combo_box_get_active(combo);
    gboolean backup  = (op == OP_BACKUP);
    gboolean restore = (op == OP_RESTORE);
    gboolean init    = (op == OP_INIT);
    gboolean delete  = (op == OP_DELETE);
    /* The repo password is required for init/backup/restore/delete and optional
     * for list (it unlocks the real per-snapshot data sizes); verify needs none. */
    gboolean needs_pw = (op != OP_VERIFY);
    /* Both restore and delete pick an existing snapshot from the drop-down. */
    gboolean pick_snap = (restore || delete);

    gtk_widget_set_sensitive(app->path_entry, backup || restore);
    gtk_widget_set_sensitive(app->path_btn,   backup || restore);
    gtk_label_set_text(GTK_LABEL(app->path_label),
                       restore ? "Restore into:" : "Source folder:");
    gtk_widget_set_sensitive(app->snap_entry, pick_snap);
    gtk_widget_set_sensitive(app->repo_pw_entry, needs_pw);
    gtk_widget_set_sensitive(app->key_pw_entry, init || backup);
    /* Re-enter fields guard against an unrecoverable typo when first setting a
     * password; only Initialise establishes the passwords, so show them there. */
    gtk_widget_set_visible(app->repo_confirm_row, init);
    gtk_widget_set_visible(app->key_confirm_row, init);

    /* Pull in the available snapshots when entering Restore or Delete. */
    if (pick_snap) refresh_snapshots(app);

    const char *labels[] = { "INITIALISE", "BACK UP", "RESTORE",
                             "LIST", "VERIFY", "DELETE" };
    gtk_button_set_label(GTK_BUTTON(app->run_button), labels[op]);
}

static void warn_dialog(App *app, const char *msg) {
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(app->window),
        GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK, "%s", msg);
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

/* Modal yes/no confirmation. Returns TRUE if the user chose to proceed. */
static gboolean confirm_dialog(App *app, const char *primary,
                               const char *secondary, const char *proceed_label) {
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(app->window),
        GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_NONE, "%s", primary);
    gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(d), "%s", secondary);
    gtk_dialog_add_buttons(GTK_DIALOG(d),
        "_Cancel", GTK_RESPONSE_CANCEL,
        proceed_label, GTK_RESPONSE_ACCEPT, NULL);
    gtk_dialog_set_default_response(GTK_DIALOG(d), GTK_RESPONSE_CANCEL);
    int resp = gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
    return resp == GTK_RESPONSE_ACCEPT;
}

static void save_last_repo(const char *repo);

static void on_run(GtkButton *b, gpointer user) {
    (void)b;
    App *app = user;
    int op = gtk_combo_box_get_active(GTK_COMBO_BOX(app->op_combo));
    const char *repo = gtk_entry_get_text(GTK_ENTRY(app->repo_entry));
    const char *path = gtk_entry_get_text(GTK_ENTRY(app->path_entry));
    const char *rpw  = gtk_entry_get_text(GTK_ENTRY(app->repo_pw_entry));
    const char *kpw  = gtk_entry_get_text(GTK_ENTRY(app->key_pw_entry));

    if (!repo || !*repo) { warn_dialog(app, "Choose a backup directory."); return; }
    if ((op == OP_BACKUP || op == OP_RESTORE) && (!path || !*path)) {
        warn_dialog(app, op == OP_BACKUP ? "Choose a folder to back up."
                                         : "Choose a folder to restore into.");
        return;
    }
    if ((op == OP_INIT || op == OP_BACKUP || op == OP_RESTORE || op == OP_DELETE)
        && (!rpw || !*rpw)) {
        warn_dialog(app, "Enter the backup password."); return;
    }
    if (strlen(rpw) >= PASSWORD_MAX || strlen(kpw) >= PASSWORD_MAX) {
        warn_dialog(app, "Password is too long."); return;
    }
    /* Initialise bakes these passwords in permanently; a hidden-entry typo here
     * would be unrecoverable, so require the re-entered copies to match. */
    if (op == OP_INIT) {
        const char *rpw2 = gtk_entry_get_text(GTK_ENTRY(app->repo_pw_confirm));
        const char *kpw2 = gtk_entry_get_text(GTK_ENTRY(app->key_pw_confirm));
        if (strcmp(rpw, rpw2) != 0) {
            warn_dialog(app, "The backup passwords do not match."); return;
        }
        if (strcmp(kpw, kpw2) != 0) {
            warn_dialog(app, "The signing passphrases do not match."); return;
        }
    }
    if (strlen(repo) >= sizeof ((Job*)0)->repo ||
        strlen(path) >= sizeof ((Job*)0)->path2) {
        warn_dialog(app, "Path is too long."); return;
    }
    /* Initialising with no signing passphrase leaves the signing key in the
     * clear — make that an explicit, informed choice rather than a silent one. */
    if (op == OP_INIT && (!kpw || !*kpw)) {
        if (!confirm_dialog(app,
                "Store the signing key without a passphrase?",
                "The snapshot signing key proves your backups are authentic. "
                "Left without a passphrase it is saved UNENCRYPTED in the backup "
                "directory, so anyone who copies that directory could forge "
                "signed snapshots.\n\n"
                "Enter a signing passphrase to protect it, or proceed unprotected.",
                "Proceed _unprotected"))
            return;
    }
    /* Deletion is irreversible and reclaims shared data — confirm explicitly. */
    if (op == OP_DELETE) {
        gchar *sel = gtk_combo_box_text_get_active_text(
                         GTK_COMBO_BOX_TEXT(app->snap_entry));
        if (!sel || !*sel) {
            g_free(sel);
            warn_dialog(app, "Select a snapshot to delete."); return;
        }
        char msg[512];
        g_snprintf(msg, sizeof msg,
            "Permanently delete snapshot \xE2\x80\x9C%s\xE2\x80\x9D?", sel);
        g_free(sel);
        if (!confirm_dialog(app, msg,
                "The snapshot record is removed and any data objects it alone "
                "referenced are deleted to reclaim space. Objects shared with "
                "other snapshots are kept. This cannot be undone.",
                "_Delete snapshot"))
            return;
    }

    /* Remember this backup directory for next launch (path only, no secrets). */
    save_last_repo(repo);

    Job *job = g_new0(Job, 1);
    job->app = app;
    job->op = op;
    sodium_mlock(job->repo_pw, sizeof job->repo_pw);
    sodium_mlock(job->key_pw, sizeof job->key_pw);
    g_strlcpy(job->repo, repo, sizeof job->repo);
    g_strlcpy(job->path2, path, sizeof job->path2);
    gchar *snap = gtk_combo_box_text_get_active_text(
                      GTK_COMBO_BOX_TEXT(app->snap_entry));
    g_strlcpy(job->snapshot, (snap && *snap) ? snap : "latest", sizeof job->snapshot);
    g_free(snap);
    g_strlcpy(job->repo_pw, rpw, sizeof job->repo_pw);
    g_strlcpy(job->key_pw, kpw, sizeof job->key_pw);

    app->cancel = 0;
    gtk_text_buffer_set_text(app->logbuf, "", 0);
    gtk_widget_set_sensitive(app->run_button, FALSE);
    set_status(app, "status-run", "\xE2\x96\xB6 Working\xE2\x80\xA6");
    app->pulsing = TRUE;
    if (app->pulse_id == 0) app->pulse_id = g_timeout_add(110, pulse_cb, app);

    app->current_job = job;
    g_application_hold(G_APPLICATION(app->gapp));

    GError *gerr = NULL;
    GThread *t = g_thread_try_new("pqsealed-worker", worker_thread, job, &gerr);
    if (!t) {
        g_application_release(G_APPLICATION(app->gapp));
        app->current_job = NULL;
        stop_pulse(app);
        gtk_widget_set_sensitive(app->run_button, TRUE);
        set_status(app, "status-err", "\xE2\x9C\x96 Could not start worker thread.");
        sodium_munlock(job->repo_pw, sizeof job->repo_pw);
        sodium_munlock(job->key_pw, sizeof job->key_pw);
        g_free(job);
        if (gerr) g_error_free(gerr);
        return;
    }
    g_thread_unref(t);
}

static void on_about(GtkButton *b, gpointer user) {
    (void)b;
    App *app = user;
    const gchar *authors[] = { "Jean-Francois Lachance-Caumartin", NULL };
    GtkWidget *d = gtk_about_dialog_new();
    GtkAboutDialog *ad = GTK_ABOUT_DIALOG(d);
    gtk_about_dialog_set_program_name(ad, "PQ-Sealed");
    gtk_about_dialog_set_version(ad, PQSEALED_VERSION);
    gtk_about_dialog_set_comments(ad,
        "Incremental, post-quantum encrypted backups.\n\n"
        "• Content-addressed, deduplicating snapshots — only new or\n"
        "  changed files are stored on each backup\n"
        "• Files sealed with a Kyber-1024 + X448 hybrid KEM whose\n"
        "  secret key is wrapped by your backup-directory password;\n"
        "  contents encrypted with XChaCha20-Poly1305 (secretstream)\n"
        "• Each snapshot manifest signed with ML-DSA-65 (FIPS 204)\n"
        "  for tamper-evident, verifiable backups\n"
        "• Restore verifies every object's hash against the signed\n"
        "  manifest\n"
        "• Hardened memory: passwords and keys stay in locked,\n"
        "  non-dumpable RAM and never hit swap");
    gtk_about_dialog_set_authors(ad, authors);
    gtk_about_dialog_set_copyright(ad, "© 2026 Jean-Francois Lachance-Caumartin");
    gtk_about_dialog_set_license_type(ad, GTK_LICENSE_MIT_X11);
    gtk_about_dialog_set_logo_icon_name(ad, "pq-sealed");
    gtk_window_set_transient_for(GTK_WINDOW(d), GTK_WINDOW(app->window));
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

/* ----- layout ----------------------------------------------------------- */

static GtkWidget *labeled_row(const char *text, GtkWidget *widget,
                              GtkWidget *extra, GtkWidget **out_label) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *lbl = gtk_label_new(text);
    gtk_widget_set_size_request(lbl, 130, -1);
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl), "field-label");
    gtk_box_pack_start(GTK_BOX(box), lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), widget, TRUE, TRUE, 0);
    if (extra) gtk_box_pack_start(GTK_BOX(box), extra, FALSE, FALSE, 0);
    if (out_label) *out_label = lbl;
    return box;
}

static void on_window_destroy(GtkWidget *w, gpointer user) {
    (void)w;
    App *app = user;
    app->window_gone = 1;
    app->cancel = 1;
    Job *job = app->current_job;
    if (!job) free_app(app);
    /* else: the worker owns app's lifetime and frees it in job_finished_idle. */
}

static void load_css(void) {
    GtkCssProvider *p = gtk_css_provider_new();
    gtk_css_provider_load_from_data(p, APP_CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(p), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(p);
}

/* ----- last-used backup directory (persisted) --------------------------- *
 * We remember only the backup directory path so the user need not re-pick it
 * each launch. Passwords and key material are NEVER written to disk. */

static char *settings_path(void) {
    return g_build_filename(g_get_user_config_dir(), "pq-sealed", "settings.ini", NULL);
}

static char *load_last_repo(void) {
    char *path = settings_path();
    GKeyFile *kf = g_key_file_new();
    char *repo = NULL;
    if (g_key_file_load_from_file(kf, path, G_KEY_FILE_NONE, NULL))
        repo = g_key_file_get_string(kf, "general", "last_repo", NULL);
    g_key_file_free(kf);
    g_free(path);
    return repo;  /* caller frees; NULL if unset */
}

static void save_last_repo(const char *repo) {
    if (!repo || !*repo) return;
    char *dir = g_build_filename(g_get_user_config_dir(), "pq-sealed", NULL);
    g_mkdir_with_parents(dir, 0700);
    g_free(dir);
    char *path = settings_path();
    GKeyFile *kf = g_key_file_new();
    g_key_file_load_from_file(kf, path, G_KEY_FILE_KEEP_COMMENTS, NULL);
    g_key_file_set_string(kf, "general", "last_repo", repo);
    g_key_file_save_to_file(kf, path, NULL);
    g_key_file_free(kf);
    g_free(path);
}

static GtkWidget *pw_entry(void) {
    GtkWidget *e = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(e), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(e), GTK_INPUT_PURPOSE_PASSWORD);
    return e;
}

static void activate(GtkApplication *gapp, gpointer user) {
    (void)user;
    App *app = g_new0(App, 1);
    app->gapp = gapp;
    load_css();

    app->window = gtk_application_window_new(gapp);
    gtk_window_set_title(GTK_WINDOW(app->window), "PQ-Sealed");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 940, 500);
    gtk_window_set_icon_name(GTK_WINDOW(app->window), "pq-sealed");
    gtk_window_set_position(GTK_WINDOW(app->window), GTK_WIN_POS_CENTER);

    GtkWidget *hb = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(hb), TRUE);
    GtkWidget *title_lbl = gtk_label_new("PQ-SEALED  \xC2\xB7  v" PQSEALED_VERSION);
    gtk_label_set_ellipsize(GTK_LABEL(title_lbl), PANGO_ELLIPSIZE_NONE);
    gtk_style_context_add_class(gtk_widget_get_style_context(title_lbl), "hb-title");
    gtk_header_bar_set_custom_title(GTK_HEADER_BAR(hb), title_lbl);
    GtkWidget *hb_about = gtk_button_new_with_label("About");
    g_signal_connect(hb_about, "clicked", G_CALLBACK(on_about), app);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(hb), hb_about);
    gtk_window_set_titlebar(GTK_WINDOW(app->window), hb);

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_style_context_add_class(gtk_widget_get_style_context(root), "root");
    gtk_container_set_border_width(GTK_CONTAINER(root), 12);
    gtk_container_add(GTK_CONTAINER(app->window), root);

    /* Brand banner spans the full width across the top. */
    GtkWidget *brand = gtk_label_new("\xF0\x9F\x9B\xA1 P Q - S E A L E D");
    gtk_label_set_xalign(GTK_LABEL(brand), 0.5);
    gtk_style_context_add_class(gtk_widget_get_style_context(brand), "brand");
    gtk_box_pack_start(GTK_BOX(root), brand, FALSE, FALSE, 0);
    GtkWidget *sub = gtk_label_new("POST-QUANTUM  ENCRYPTED  BACKUPS");
    gtk_label_set_xalign(GTK_LABEL(sub), 0.5);
    gtk_style_context_add_class(gtk_widget_get_style_context(sub), "subtitle");
    gtk_box_pack_start(GTK_BOX(root), sub, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root),
                       gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 6);

    /* Two columns: controls on the left, log on the right. */
    GtkWidget *cols = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 16);
    gtk_box_pack_start(GTK_BOX(root), cols, TRUE, TRUE, 0);

    GtkWidget *left = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_size_request(left, 390, -1);
    gtk_box_pack_start(GTK_BOX(cols), left, FALSE, FALSE, 0);

    GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_pack_start(GTK_BOX(cols), right, TRUE, TRUE, 0);

    /* --- left column: controls --- */

    /* Backup directory */
    app->repo_entry = gtk_entry_new();
    char *last_repo = load_last_repo();
    /* Only pre-fill the remembered directory if it still exists; otherwise fall
     * back to the first-run default rather than offering a dead path. */
    gboolean have_last = last_repo && *last_repo &&
        g_file_test(last_repo, G_FILE_TEST_IS_DIR);
    gtk_entry_set_text(GTK_ENTRY(app->repo_entry),
                       have_last ? last_repo : "pqsealed-backup");
    g_free(last_repo);
    GtkWidget *repo_btn = gtk_button_new_with_label("Browse…");
    g_signal_connect(repo_btn, "clicked", G_CALLBACK(on_browse_repo), app);
    g_signal_connect(app->repo_entry, "changed", G_CALLBACK(on_repo_changed), app);
    gtk_box_pack_start(GTK_BOX(left),
        labeled_row("Backup directory:", app->repo_entry, repo_btn, NULL),
        FALSE, FALSE, 0);

    /* Operation */
    app->op_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->op_combo), "Initialise backup directory");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->op_combo), "Back up a folder");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->op_combo), "Restore a snapshot");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->op_combo), "List snapshots");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->op_combo), "Verify snapshots");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->op_combo), "Delete a snapshot");
    gtk_box_pack_start(GTK_BOX(left),
        labeled_row("Operation:", app->op_combo, NULL, NULL), FALSE, FALSE, 0);

    /* Source / destination folder */
    app->path_entry = gtk_entry_new();
    app->path_btn = gtk_button_new_with_label("Browse…");
    g_signal_connect(app->path_btn, "clicked", G_CALLBACK(on_browse_path), app);
    gtk_box_pack_start(GTK_BOX(left),
        labeled_row("Source folder:", app->path_entry, app->path_btn,
                    &app->path_label), FALSE, FALSE, 0);

    /* Snapshot (restore) — a drop-down populated from the chosen repo. */
    app->snap_entry = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->snap_entry), "latest");
    gtk_combo_box_set_active(GTK_COMBO_BOX(app->snap_entry), 0);
    gtk_box_pack_start(GTK_BOX(left),
        labeled_row("Snapshot:", app->snap_entry, NULL, &app->snap_label),
        FALSE, FALSE, 0);

    /* Backup password */
    app->repo_pw_entry = pw_entry();
    gtk_widget_set_tooltip_text(app->repo_pw_entry,
        "Encrypts your file contents. Required for init, backup and restore. "
        "If you lose it, the backup cannot be decrypted — there is no recovery.");
    GtkWidget *rrev = gtk_check_button_new_with_label("Reveal");
    g_signal_connect(rrev, "toggled", G_CALLBACK(reveal_toggled), app->repo_pw_entry);
    gtk_box_pack_start(GTK_BOX(left),
        labeled_row("Backup password:", app->repo_pw_entry, rrev, NULL),
        FALSE, FALSE, 0);

    /* Confirm backup password (shown only for Initialise) */
    app->repo_pw_confirm = pw_entry();
    GtkWidget *rrev2 = gtk_check_button_new_with_label("Reveal");
    g_signal_connect(rrev2, "toggled", G_CALLBACK(reveal_toggled), app->repo_pw_confirm);
    app->repo_confirm_row =
        labeled_row("Confirm password:", app->repo_pw_confirm, rrev2, NULL);
    gtk_box_pack_start(GTK_BOX(left), app->repo_confirm_row, FALSE, FALSE, 0);

    /* Signing-key passphrase */
    app->key_pw_entry = pw_entry();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app->key_pw_entry),
        "optional — blank stores the signing key unencrypted");
    gtk_widget_set_tooltip_text(app->key_pw_entry,
        "Encrypts the snapshot SIGNING key (keys/snapshot.key), which proves your "
        "snapshots are authentic. Separate from the backup password.\n\n"
        "Leave it blank and the signing key is stored UNENCRYPTED in the backup "
        "directory: anyone who copies the directory could forge signed snapshots. "
        "Set a passphrase to protect it at rest.");
    GtkWidget *krev = gtk_check_button_new_with_label("Reveal");
    g_signal_connect(krev, "toggled", G_CALLBACK(reveal_toggled), app->key_pw_entry);
    gtk_box_pack_start(GTK_BOX(left),
        labeled_row("Signing pass:", app->key_pw_entry, krev, &app->key_pw_label),
        FALSE, FALSE, 0);

    /* Confirm signing passphrase (shown only for Initialise) */
    app->key_pw_confirm = pw_entry();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app->key_pw_confirm),
        "re-enter signing passphrase (leave blank if unset)");
    GtkWidget *krev2 = gtk_check_button_new_with_label("Reveal");
    g_signal_connect(krev2, "toggled", G_CALLBACK(reveal_toggled), app->key_pw_confirm);
    app->key_confirm_row =
        labeled_row("Confirm pass:", app->key_pw_confirm, krev2, NULL);
    gtk_box_pack_start(GTK_BOX(left), app->key_confirm_row, FALSE, FALSE, 0);

    /* Action button */
    app->run_button = gtk_button_new_with_label("INITIALISE");
    gtk_widget_set_hexpand(app->run_button, TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(app->run_button),
                                "action-button");
    g_signal_connect(app->run_button, "clicked", G_CALLBACK(on_run), app);
    gtk_box_pack_start(GTK_BOX(left), app->run_button, FALSE, FALSE, 3);

    /* Progress + status */
    app->progress = gtk_progress_bar_new();
    gtk_box_pack_start(GTK_BOX(left), app->progress, FALSE, FALSE, 0);
    app->status = gtk_label_new("Ready.");
    gtk_label_set_xalign(GTK_LABEL(app->status), 0.0);
    gtk_label_set_line_wrap(GTK_LABEL(app->status), TRUE);
    gtk_box_pack_start(GTK_BOX(left), app->status, FALSE, FALSE, 0);

    /* --- right column: log --- */
    GtkWidget *log_lbl = gtk_label_new("LOG");
    gtk_label_set_xalign(GTK_LABEL(log_lbl), 0.0);
    gtk_style_context_add_class(gtk_widget_get_style_context(log_lbl), "field-label");
    gtk_box_pack_start(GTK_BOX(right), log_lbl, FALSE, FALSE, 0);

    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(scroll, 320, -1);
    GtkWidget *logview = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(logview), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(logview), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(logview), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(logview), GTK_WRAP_WORD_CHAR);
    app->logbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(logview));
    gtk_container_add(GTK_CONTAINER(scroll), logview);
    gtk_box_pack_start(GTK_BOX(right), scroll, TRUE, TRUE, 0);

    g_signal_connect(app->op_combo, "changed", G_CALLBACK(on_op_changed), app);
    g_signal_connect(app->window, "destroy", G_CALLBACK(on_window_destroy), app);

    gtk_combo_box_set_active(GTK_COMBO_BOX(app->op_combo), OP_INIT);  /* sets field state */

    gtk_widget_show_all(app->window);
}

/* Keep secrets off disk: no core dumps, not ptrace/-/proc dumpable. */
static void harden(void) {
    struct rlimit rl = { 0, 0 };
    setrlimit(RLIMIT_CORE, &rl);
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) {
        g_printerr("Failed to initialise libsodium.\n");
        return 1;
    }
    harden();
    GtkApplication *gapp = gtk_application_new(APP_ID, G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(gapp, "activate", G_CALLBACK(activate), NULL);
    int status = g_application_run(G_APPLICATION(gapp), argc, argv);
    g_object_unref(gapp);
    return status;
}

# Wisp's Hermes plugin

Hands the tasks that need Wisp's services or Private Folders from [Hermes](https://github.com/NousResearch/hermes-agent)
to Wisp's `ask_wisp`, and registers `hermes wisp connect <url>`, `/wisp` and `/wisp-model` (`/wisp_model` in
Telegram). It needs Hermes v0.21.6 or later.

Hermes's own commands fill a Telegram bot's 60-slot command menu, so `hermes wisp connect` (which `wisp integrate
hermes` runs) puts `/wisp` and `/wisp_model` first, ahead of any names already in the profile's
`platforms.telegram.extra.command_menu.priority`; the gateway shows them from its next start. `--remove` takes them out
again. Typed, both work whether the menu lists them or not, and `/commands` lists every command.

## One machine

Don't install the plugin from here: `wisp integrate hermes` lays out the copy embedded in the `wisp` binary (this
repository's committed code) in every Hermes profile, connects it over loopback, and sandboxes Hermes away from Wisp's
zone: its data directory, the Desk root, the Private Folders and the files outside them Wisp reads its secrets from
(`wisp serve --config`, `WISP_MASTER_KEY_FILE`). On Linux such a file reads as empty inside the sandbox, and a write to it
goes nowhere.

1. Install Wisp, answering its two questions: whether to start the Runtime in the background now and at every login, and
   whether to log in now.

   ```sh
   curl -fsSL https://usewisp.io/runtime/install.sh | sh
   ```

2. Open a new terminal, or load the `PATH` into this one with the `source` line the installer prints (e.g.
   `source ~/.zshrc`). Until then `wisp` is not found, or is another install's.

3. Wire Wisp into every Hermes profile. It asks whether to move Hermes's MCP servers into Wisp.

   ```sh
   wisp integrate hermes
   ```

4. On Linux, bubblewrap is required for Wisp inside Hermes, not only for `bash_run`'s sandbox. When it is missing, or
   Ubuntu's AppArmor blocks it, `integrate` prints the fix as "Before the restart: …": `sudo apt install bubblewrap`, or a
   `sudo sh -c '…'` line that installs a bwrap AppArmor profile. Run it as printed; with no `sudo`, run it as root
   without its leading `sudo`.

5. Restart Hermes, and quit any open `hermes` CLI:

   ```sh
   hermes gateway restart --all
   ```

   Until each Hermes has stopped, it runs without the sandbox.

Then:

- A Confirmation Wisp raises shows in Hermes's own approval panel, and is denied when nobody answers within Hermes's
  5 minutes (`approvals.timeout`). One "Allow once" covers that tool for the rest of the task, except where Wisp's own
  rules ask every time (a Judge escalation, an "Always ask" Rule).
- A Hermes cron job or `hermes chat -q` has no one to answer, so it can use only the Wisp tools already allowed. Allow
  them beforehand: `wisp permissions set <tool> allow`.
- With Wisp's Auto Mode on, the Judge answers Hermes's Wisp calls first: Hermes's panel shows only what it escalates, and
  a tool set to `always_ask` always reaches it.
- The model Wisp uses for Hermes is chosen with `/wisp-model` in the Hermes CLI, `/wisp_model` in Telegram.

### Asked from a chat

When the user asks Hermes in a chat (Telegram, Slack) to install Wisp or this plugin, Hermes runs these steps itself,
in its terminal. There is no terminal for the installer to ask its questions on, so they are answered up front.

Hermes does not read `~/.wisp` or `~/.config/wisp` itself, not even while a step fails: they hold Wisp's secrets. It asks
`~/.wisp/bin/wisp status` for the Runtime's state, and reads its log with `journalctl --user -u wisp` on Linux or from
`~/.wisp/logs/serve.log` on macOS.

1. Install Wisp and start it as a background service:

   ```sh
   curl -fsSL https://usewisp.io/runtime/install.sh | WISP_SERVICE=1 sh
   ```

2. Sign in. Start the login in the background with a pty (Hermes: `terminal(background=true, pty=true)`): it prints a
   URL and waits for a line.

   ```sh
   ~/.wisp/bin/wisp login --manual
   ```

   Send the user the URL exactly as printed, in a code block, and ask them to sign in and send back the URL their browser
   lands on. Write that URL to the process followed by a newline. The login expires after 5 minutes; then start it again.

3. Wire Wisp into Hermes, without the question about moving MCP servers:

   ```sh
   ~/.wisp/bin/wisp integrate hermes --skip-connectors
   ```

   Run from Hermes's own terminal, Hermes reloads under this command as it enables the plugin, and the turn ends there.
   `integrate` goes on, and what it says from then on is in `wisp-integrate.log` in Hermes's home (`~/.hermes`). On
   Linux, if the log names a fix "Before the restart", the user runs it as root (Hermes cannot: no `sudo` works inside
   its sandbox).

That reload is the last step: no restart command follows. The user checks the result with a Wisp task, or Hermes with
`hermes mcp test wisp`; Hermes can read the log to say how `integrate` ended. Hermes asks the user to send `/restart` in
the chat only if the chat stays locked, or on macOS. `hermes gateway restart` is for a terminal: Hermes refuses it from
inside a supervised gateway.

`~/.wisp/bin` reaches `PATH` only in new shells, hence the full path. Hermes's MCP servers can be moved into Wisp later,
from a terminal, with `wisp integrate hermes --connectors`.

## Two machines: Wisp on one, Hermes on another

The Runtime binds `127.0.0.1` as always, and the secret Hermes holds is the Host Agent Credential, which opens the
Runtime's `/mcp` and nothing else.

1. On the Runtime's machine, put https in front of it. With Tailscale Serve, enable Serve and HTTPS for the tailnet once
   (in its admin console), then run the command below, which prints the machine's https name. Caddy as a reverse proxy
   works as well, or an `ssh -L` tunnel kept up as a service on Hermes's machine (then the URL in step 4 is
   `http://127.0.0.1:<port>/mcp`).

   ```sh
   tailscale serve --bg 3008
   ```

2. There, make the Host Agent Credential (printed once) for that name, which also adds the name to the Runtime's
   `allowedHosts`. The Runtime answers to it once restarted: `systemctl --user restart wisp` on Linux,
   `launchctl kickstart -k gui/$(id -u)/io.usewisp.runtime` on macOS, or stop and start `wisp serve`.

   ```sh
   wisp tokens create --name hermes --host-agent --public-url https://<that name>
   ```

3. On Hermes's machine, install the plugin:

   ```sh
   hermes plugins install ConfidentialCrabComputing/wisp-hermes-plugin/wisp --enable
   ```

   The plugin is the repository's `wisp/` folder: Hermes clones and scans only that folder and installs it as `wisp`.
   Its scanner shows a CAUTION verdict and its findings, then "Decision: BLOCKED" with "Use --force to override", then
   asks "Install anyway? [y/N]": answer `y`. With no terminal it refuses; add `--force` there.

4. Connect it. `connect` asks for the Host Agent Credential and reads it without echo; then check the endpoint answers:

   ```sh
   hermes wisp connect https://<that name>/mcp
   hermes mcp test wisp
   ```

5. If it connected only after a fix (Serve switched on, the Runtime restarted), Hermes gets Wisp back by itself within
   seconds, or at once with `hermes gateway restart`.

Hermes's install-time scanner gives this plugin a `caution` verdict, with 14 findings, all in the plugin's own code:

- `sandbox.py` starts processes: `wisp sandbox-exec` to build the sandbox, bubblewrap to start Hermes inside it, and
  `systemctl show` to tell whether a service manager restarts Hermes. It reads its own `/proc/self` (`mountinfo`,
  `cgroup`, `fd`) to see whether it is already sandboxed, which service it runs under and which file descriptors to
  pass on. A comment names `/proc/self`, and a message says `sudo apt install bubblewrap` when bubblewrap is missing.
- `connect.py` runs `hermes config set` to register Wisp's endpoint, and its comments name the commands (`printenv`,
  `cat ~/.hermes/.env`) by which Hermes's model could read the credential.
- `zone.py` holds a pattern of control characters, which it strips from the zone's text before Hermes's prompt sees it.

The URL is `https://` or loopback; plain http off loopback is refused. `hermes wisp connect --remove` reverses it.
Nothing of Wisp's is on Hermes's disk, so there is no sandbox and no `wisp doctor` here.

## Known limits

- Whoever holds the credential is Hermes: a prompt-injected Hermes can approve Wisp's Confirmation Prompts itself. It
  cannot read the data, but it can make Wisp move it out.
- Anyone Hermes lets in uses Wisp as its owner.
- Hermes's model can read the credential from its terminal's environment, so it can call the endpoint outside Hermes.
- On one machine, Hermes's model can switch the plugin off and restart Hermes, which is neither prevented nor detected
  at run time.
- On one machine, a server moved into Wisp stays out of Hermes only while its keys are gone from Hermes: its entries in
  the profile's `.env` and `mcp-tokens/<server>.json` in the profile's home. A model set on it can switch the server
  back on past the hook's text checks.
- On one machine, the sandbox stops Hermes reading Wisp's zone itself, not a model set on escaping it: anything Hermes
  asks an unsandboxed process to run (an app it opens or scripts, a shell startup file or a tool on PATH it rewrites)
  runs outside the sandbox.
- On one machine, the Runtime replaces its own agent token each time a sandboxed Hermes process starts, so a token
  Hermes's model saw before the sandbox stops working. A Hermes process still running unsandboxed (a CLI open since
  before `wisp integrate hermes`) can read the new token as well, until it stops.
- Under Wisp's sandbox, Hermes's browser runs without Chrome's own sandbox: Chrome's cannot start inside Wisp's, so the
  plugin adds `--no-sandbox` to `AGENT_BROWSER_ARGS`. A Hermes that runs without Wisp's sandbox keeps Chrome's.
- On Linux, `sudo` and other setuid programs do not work inside the sandboxed Hermes: bubblewrap always sets
  `no_new_privs`, as without it any setuid program inside would regain root and undo the sandbox. Run a command that
  needs root outside Hermes.
- On Linux, a Hermes running as root has Private Folders hidden from ordinary reads only: root reaches them through
  `umount`, `/proc/<pid>/root` or the raw disk. No place on one machine is out of root's reach, so run Hermes as a
  regular user to keep it out.
- A sandbox start that fails leaves Hermes running without the sandbox, saying so on stderr and in the log. Exiting
  instead would keep Hermes from starting. A process left from an earlier Hermes, or an `LD_PRELOAD` in its `.env`, can
  use this at the next start.
- While Wisp's Runtime is stopped or restarting (every `wisp update` restarts it), or its endpoint cannot be reached,
  Hermes says Wisp is not answering and does not do Wisp's tasks another way. After a few failed reconnects Hermes parks
  the `wisp` server and retries it only every 5 minutes, so the plugin asks Hermes to reconnect it every 10 seconds:
  once a Runtime on this machine (or its `ssh -L` tunnel) takes connections again, and at each try for a Runtime on
  another machine. An open session gets `ask_wisp` back from its next message, but a session that started while Wisp
  was not answering keeps that in its prompt, so start a new one (`/new`). If Wisp is still unavailable in Hermes while
  `hermes mcp test wisp` succeeds, restart Hermes (`hermes gateway restart`). Under a gateway that serves several
  profiles, only the default profile is reconnected this way; the others wait for Hermes's own 5-minute retry.
- On Linux, a gateway that enables the plugin while it runs (`wisp integrate hermes` run from Hermes's own terminal)
  restarts into the sandbox in place, and the turn that ran it is lost. Hermes pauses that chat until it is sent
  `/discard`; no `/restart` is needed. A chat opened in the 30 seconds before stays locked until `/restart`.
- On Windows the plugin is for connecting to a Wisp on another machine. A zone on the same Windows machine is not
  protected: there is no sandbox, and the check on Hermes's tool calls is untested there.

## Tests

```sh
python3 -m unittest discover -s tests
```

Standard library only, against the fake `hermes` in `tests/fake`. `test_install.py` needs a real `hermes` on PATH and
skips without one. Linux's sandbox tests need a wisp-agent checkout (`$WISP_AGENT_REPO`, else `../wisp-agent`) and
bubblewrap, as root on Ubuntu, and skip without them. wisp-agent is private, so without access to it they skip.

## Changing the plugin

The plugin's code is in `wisp/`. The `wisp` binary embeds that folder at this repository's committed HEAD. After a
commit here, run `pnpm run hermes-plugin:sync` in wisp-agent and commit the archive there.

## License

[MIT](LICENSE)

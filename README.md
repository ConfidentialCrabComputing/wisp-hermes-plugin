# Wisp's Hermes plugin

Hands the tasks that need Wisp's services or Private Folders from [Hermes](https://github.com/NousResearch/hermes-agent)
to Wisp's `ask_wisp`, and registers `hermes wisp connect <url>`, `/wisp` and `/wisp_model`. It needs Hermes
v0.21.6 or later.

## Two machines: Wisp on one, Hermes on another

On the Runtime's machine, make the credential (printed once) and put https in front of the Runtime, which binds
`127.0.0.1` as always (Tailscale Serve, Caddy), or keep an `ssh -L` as a service on Hermes's machine:

```sh
wisp tokens create --name hermes --host-agent
```

On Hermes's machine, install the plugin and connect it. `connect` reads the credential from stdin, without echo:

```sh
hermes plugins install ConfidentialCrabComputing/wisp-hermes-plugin/wisp --enable
hermes wisp connect https://wisp.example.ts.net/mcp
```

The plugin is the repository's `wisp/` folder: Hermes clones and scans only that folder and installs it as `wisp`.

Hermes's install-time scanner gives this plugin a `caution` verdict, with 14 findings, all in the plugin's own code:

- `sandbox.py` starts processes: `wisp sandbox-exec` to build the sandbox, bubblewrap to start Hermes inside it, and
  `systemctl show` to tell whether a service manager restarts Hermes. It reads its own `/proc/self` (`mountinfo`,
  `cgroup`, `fd`) to see whether it is already sandboxed, which service it runs under and which file descriptors to
  pass on. A comment names `/proc/self`, and a message says `sudo apt install bubblewrap` when bubblewrap is missing.
- `connect.py` runs `hermes config set` to register Wisp's endpoint, and its comments name the commands (`printenv`,
  `cat ~/.hermes/.env`) by which Hermes's model could read the credential.
- `zone.py` holds a pattern of control characters, which it strips from the zone's text before Hermes's prompt sees it.

In a terminal, Hermes lists the findings and asks whether to go on. With no terminal it refuses unless you add
`--force` to `hermes plugins install`.

The URL is `https://` or loopback; plain http off loopback is refused. `hermes wisp connect --remove` reverses it.
`hermes mcp test wisp` shows whether the endpoint answers. Nothing of Wisp's is on Hermes's disk, so there is no
sandbox and no `wisp doctor` here.

## One machine

Don't install from here: `wisp integrate hermes` lays out the copy embedded in the `wisp` binary (this repository's
committed code) in every Hermes profile, connects it over loopback, and sandboxes Hermes away from Wisp's zone: its data
directory, the Desk root, the Private Folders and the files outside them Wisp reads its secrets from (`wisp serve
--config`, `WISP_MASTER_KEY_FILE`). On Linux such a file reads as empty inside the sandbox, and a write to it goes nowhere.

### Asked from a chat

When the user asks Hermes in a chat (Telegram, Slack) to install Wisp or this plugin, Hermes runs these steps itself,
in its terminal. There is no terminal for the installer to ask its questions on, so they are answered up front:

1. Install Wisp and start it as a background service:

   ```sh
   curl -fsSL https://usewisp.io/runtime/install.sh | WISP_SERVICE=1 sh
   ```

2. Sign in. Start the login as a background process: it prints a URL and waits for a line on stdin.

   ```sh
   ~/.wisp/bin/wisp login --manual
   ```

   Send the URL to the user, ask them to sign in and to send back the URL their browser lands on, then write that URL
   to the process's stdin.

3. Wire Wisp into Hermes, without the question about moving MCP servers:

   ```sh
   ~/.wisp/bin/wisp integrate hermes --skip-connectors
   ```

4. Restart the gateway, which loads the plugin and its sandbox:

   ```sh
   hermes gateway restart
   ```

`~/.wisp/bin` reaches `PATH` only in new shells, hence the full path. Hermes's MCP servers can be moved into Wisp later,
from a terminal, with `wisp integrate hermes --connectors`.

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

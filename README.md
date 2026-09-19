# OTP Converter

Convert an [Open Authenticator](https://github.com/openauthenticator-app/openauthenticator) backup into plain text containing one `otpauth://` URI per line.

The output can be imported into Ente Auth using its plain-text import option, or into any other authenticator app that supports plain-text `otpauth://` files.

## Browser tool

The browser version runs locally. It does not upload the backup or password.

Open [`index.html`](index.html) directly in your browser, then:

1. Select the `.bak` backup file.
2. Enter the backup password.
3. Select **Convert**.
4. Click the copy button to copy the output.

## Node.js CLI

The command-line version is in the [`nodejs/`](nodejs/) directory.

Requirements:

- Node.js 18 or later
- npm

Install its dependencies:

```sh
cd nodejs
npm install
```

Convert a backup to a file:

```sh
node otp-converter.js /path/to/backup.bak --password 'YOUR_PASSWORD' --out otpauth.txt
```

To print the result to the terminal instead:

```sh
node otp-converter.js /path/to/backup.bak --password 'YOUR_PASSWORD'
```

Options:

- `--password`, `-p` — the backup password. If omitted, the converter prompts for it.
- `--out`, `-o` — the output file. If omitted, the URIs are printed to the terminal.
- `--help`, `-h` — show usage information.

Keep the backup password and generated output private. Delete the output file when you no longer need it.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Dependencies

The browser and Node.js versions use [hash-wasm](https://github.com/DanielBaulig/hash-wasm), which is licensed under the MIT License.

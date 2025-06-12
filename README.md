# VOPRF Server

A VOPRF (Verifiable Oblivious Pseudorandom Function) server implementation built with TypeScript, Express.js, and Node.js.

This server implements the VOPRF protocol as defined in [RFC 9497](https://doi.org/10.17487/RFC9497) using the [Cloudflare VOPRF-TS library](https://github.com/cloudflare/voprf-ts).

## Setup

1. Install dependencies:

   ```bash
   npm install
   ```

2. Create a `.env` file (optional):
   ```bash
   PORT=8001
   IP=127.0.0.1
   SERVICE_NAME=voprf-server
   NODE_ENV=development
   ```

## Development

- **Start development server** (with hot reload):

  ```bash
  npm run dev
  ```

- **Build the project**:

  ```bash
  npm run build
  ```

- **Start production server**:
  ```bash
  npm start
  ```

## Code Quality

- **Lint code**:

  ```bash
  npm run lint
  ```

- **Fix linting issues**:

  ```bash
  npm run lint:fix
  ```

- **Format code**:

  ```bash
  npm run format
  ```

- **Check formatting**:
  ```bash
  npm run format:check
  ```

## API Endpoints

### General

- `GET /ping` - Health check endpoint that returns `{"reply": "pong"}`

### VOPRF Endpoints

- `GET /voprf/public-key` - Get the server's public key for VOPRF verification
- `POST /voprf/evaluate` - Perform blind evaluation of client requests

## VOPRF Usage

### Get Public Key

```bash
curl http://localhost:8001/voprf/public-key
```

Response:

```json
{
  "publicKey": "base64-encoded-public-key",
  "suite": "P384-SHA384"
}
```

### Blind Evaluation

```bash
curl -X POST http://localhost:8001/voprf/evaluate \
  -H "Content-Type: application/json" \
  -d '{"evaluationRequest": "base64-encoded-evaluation-request"}'
```

### Client Example

Run the included client example to see the full VOPRF protocol in action:

```bash
# Start the server in one terminal
npm run dev

# Run the client example in another terminal
npm run example:client
```

## Project Structure

```
src/
├── index.ts        # Application entry point
├── app.ts          # Express app configuration
├── config/
│   └── index.ts    # Environment configuration
└── voprf/
    └── routes.ts   # VOPRF server endpoints and logic

examples/
└── voprf-client.ts # Example VOPRF client implementation
```

## VOPRF Protocol

The VOPRF (Verifiable Oblivious Pseudorandom Function) protocol allows a client to obtain pseudorandom function evaluations from a server without revealing the input to the server. The server cannot learn the client's input, and the client can verify that the server used the correct private key.

**Protocol Flow:**

1. Client requests server's public key
2. Client blinds their input and sends an evaluation request
3. Server performs blind evaluation and returns the result
4. Client unblinds the result to get the final PRF output

This implementation uses the P384-SHA384 suite for cryptographic operations.

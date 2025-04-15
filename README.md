flow:

sign-on: make user's salt and verifier
auth: create session handshake for making client proof
client-proof-gen: making client proof for proving by server
auth-proof: proving the client proof, and making strong-proof for client when proof is valid
client-strong-proof: client can get identical session key with strong-proof from server

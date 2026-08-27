# Huihui AI Assistant

frontend az index.html. backendbe ezt a lodelt integráld backendbe ezt a modelt:import os

from openai import OpenAI

client = OpenAI(

    base_url="https://ksisjsjauxhskajxhakykyus--ep-huihui-qwen3-8-27b-ablitera-a6178a.eu-west.modal.direct/v1",

    api_key=f"{os.environ['MODAL_PROXY_TOKEN_ID']}.{os.environ['MODAL_PROXY_TOKEN_SECRET']}",

)

stream = client.chat.completions.create(

    model="huihui-ai/Huihui-Qwen3.8-27B-abliterated",

    messages=[

        {

            "role": "system",

            "content": "You are a concise technical assistant.",

        },

        {

            "role": "user",

            "content": "Explain why low latency matters for LLM endpoints in three bullets.",

        },

    ],

    temperature=0.3,

    max_tokens=2048,

    top_p=0.9,

    stream=True,

    extra_body={"reasoning": {"enabled": True}},

    extra_headers={

        "Modal-Session-ID": os.environ["MODAL_SESSION_ID"],

    },

)

for chunk in stream:

    delta = chunk.choices[0].delta.content

    if delta:

        print(delta, end="", flush=True)    The backend must always be implemented in a single file, and the frontend must always be contained in a single index.html file, including all subpages. MODAL_PROXY_TOKEN_ID

wk-vvorCkeL5DaeGjAtopf2ZL

Copy

MODAL_PROXY_TOKEN_SECRETMatching token secret: shown once when it's created   MODAL_TOKEN_ID=wk-vvorCkeL5DaeGjAtopf2ZL

MODAL_TOKEN_SECRET=ws-v3oi61p64N3Ijh8MsrFa3l

MODAL_AUTH_TOKEN=wk-vvorCkeL5DaeGjAtopf2ZL.ws-v3oi61p64N3Ijh8MsrFa3l

Copy the token secret and save it somewhere. This is the last time you can see the token secret!

Token ID

wk-vvorCkeL5DaeGjAtopf2ZL

Token Secret

ws-v3oi61p64N3|jh8MsrFa3l

t Copy

When you make requests to a webhook that has proxy auth enabled, you will need to include the following header:

Modal-Key: wk-vvorCkeL5DaeGjAtopf2ZL

Modal-Secret: ws-v30i61p64N3Ijh8MsrFa3l

Alternatively, on Auto Endpoints and Modal Servers you can pass the same credential as a single Authorization header. This is useful for OpenAl-compatible clients and gateways that only accept a bearer token:

Authorization: Bearer wk-vvorCkeL5DaeGjAtopf2ZL.ws-v3oi61p64N3Ijh8MsrFa3l

This project was built with [Lovable](https://lovable.dev).

**Live app**: https://pakkoskurva.lovable.app

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/ddae7d6e-e336-436e-a73c-2e5675b816fa).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```

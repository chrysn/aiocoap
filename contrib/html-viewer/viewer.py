# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""This file is intended to be run in pyodide by the accompanying index.html"""

import aiocoap
import aiocoap.proxy.client
import js
import asyncio
import html


async def outer_main():
    status = js.document.getElementById("status").firstChild
    status.data = "Starting up"

    try:
        await main()
    except BaseException as e:
        status.data = f"Crashed: {e!r}"
        raise
    else:
        status.data = "Terminated (?)"


async def main():
    output = js.document.getElementById("output")
    status = js.document.getElementById("status").firstChild

    uri = js.document.getElementById("uri")
    proxy = js.document.getElementById("proxy")
    go = js.document.getElementById("go")
    mainform = js.document.getElementById("mainform")

    clicks = asyncio.Queue()

    # the proxy URI is absolute and even pathless, so no fragment should be in there anyway
    fragment = js.window.location.hash.removeprefix("#")
    if fragment:
        (proxy.value, _, uri.value) = fragment.partition("#")

    def onsubmit(event):
        clicks.put_nowait(None)
        return False

    mainform.onsubmit = onsubmit
    uri.disabled = False
    proxy.disabled = False
    go.disabled = False

    protocol = await aiocoap.Context.create_client_context()

    while True:
        output.innerHTML = ""
        js.document.title = uri.value
        js.window.location.hash = "#" + proxy.value + "#" + uri.value
        task = asyncio.create_task(
            observe(protocol, status, output, uri.value, proxy.value)
        )
        await clicks.get()
        task.cancel()
        status.value = "Starting over with new address…"


async def observe(protocol, status, output, uri, proxy):
    # FIXME: udp6 doesn't fail prettily on pyodide, catching
    if uri.partition("://")[0] not in ["coap+ws", "coaps+ws"] and not proxy:
        status.data = "Error: Only the URI schemes 'coap+ws' or 'coaps+ws' are supported without a configured proxy."
        return
    try:
        status.data = "Sending request…"
        while True:
            msg = aiocoap.Message(code=aiocoap.GET, uri=uri, observe=0)

            if proxy:
                # FIXME: aiocoap's proxying does not set proxy-scheme right, doing it manually
                # requester = aiocoap.proxy.client.ProxyForwarder(proxy, protocol)
                requester = protocol

                host, port = aiocoap.util.hostportsplit(msg.remote.hostinfo)
                msg.opt.uri_port = port
                msg.opt.uri_host = host
                msg.opt.proxy_scheme = msg.remote.scheme

                to_proxy = aiocoap.Message(uri=proxy)
                msg.remote = to_proxy.remote

                # and furthermore there is something wrong with the proxy
                # (sending an observable result and then 5.00), so skipping
                # observe here
                msg.opt.observe = None
            else:
                requester = protocol

            request = requester.request(msg)

            def render(response):
                status.data = f"Live data ({response.code})…"
                prettified = pretty(response)
                output.innerHTML = (
                    prettified
                    or '<p style="color:gray;font-size:small;">Response was empty</p>'
                )

            first = await request.response
            render(first)

            if first.opt.observe is None:
                status.data = f"Received response ({first.code})"
                break

            async for response in request.observation:
                render(response)

            status.data += ", and then lost observation; waiting before retry…"
            await asyncio.sleep(10)
            status.data = "Retrying…"
    except Exception as e:
        status.data = f"Failed permanently, please try different URI: {e!r}"


def pretty(message):
    # FIXME: This is part of the Message._repr_html_, but should be available
    # for standalone use without rendering code and options
    from aiocoap.util.prettyprint import pretty_print, lexer_for_mime

    (notes, mediatype, text) = pretty_print(message)
    import pygments
    from pygments.formatters import HtmlFormatter

    try:
        lexer = lexer_for_mime(mediatype)
        text = pygments.highlight(text, lexer, HtmlFormatter())
    except pygments.util.ClassNotFound:
        text = html.escape(text)
    return (
        "<div>"
        + "".join(
            f'<p style="color:gray;font-size:small;">{html.escape(n)}</p>'
            for n in notes
        )
        + f"<pre>{text}</pre>"
        + "</div>"
    )

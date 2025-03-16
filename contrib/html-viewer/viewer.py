# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""This file is intended to be run in pyodide by the accompanying index.html"""

import aiocoap
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
    go = js.document.getElementById("go")
    uri_row = js.document.getElementById("uri-row")

    clicks = asyncio.Queue()

    fragment = js.window.location.hash.lstrip("#")
    if fragment:
        uri.value = fragment

    def onsubmit(event):
        clicks.put_nowait(None)
        return False

    uri_row.onsubmit = onsubmit
    uri.disabled = False
    go.disabled = False

    protocol = await aiocoap.Context.create_client_context()

    while True:
        js.document.title = uri.value
        js.window.location.hash = uri.value
        task = asyncio.create_task(observe(protocol, status, output, uri.value))
        await clicks.get()
        task.cancel()
        status.value = "Starting over with new address…"


async def observe(protocol, status, output, uri):
    try:
        status.data = "Sending request…"
        while True:
            msg = aiocoap.Message(code=aiocoap.GET, uri=uri, observe=0)
            request = protocol.request(msg)

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

            status.data = "Lost observation, waiting before retry…"
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

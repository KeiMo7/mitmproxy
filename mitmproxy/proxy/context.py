from typing import Any
from typing import TYPE_CHECKING

from mitmproxy import connection
from mitmproxy.options import Options

if TYPE_CHECKING:
    import mitmproxy.proxy.layer


class Context:
    """
    The context object provided to each protocol layer in the proxy core.
    """

    client: connection.Client
    """The client connection."""
    server: connection.Server
    """
    The server connection.

    For practical reasons this attribute is always set, even if there is not server connection yet.
    In this case the server address is `None`.
    """
    options: Options
    """
    Provides access to options for proxy layers. Not intended for use by addons, use `mitmproxy.ctx.options` instead.
    """
    layers: list["mitmproxy.proxy.layer.Layer"]
    """
    The protocol layer stack.
    """
    extra: dict[str, Any]
    """
    Arbitrary data attached to this context.

    In contrast to the other attributes, this dictionary is shared between a
    context and all its forks. This makes it possible to tag a connection with
    data that must remain visible to layers which receive a forked context,
    for example client playback.
    """

    def __init__(
        self,
        client: connection.Client,
        options: Options,
    ) -> None:
        self.client = client
        self.options = options
        self.server = connection.Server(
            address=None, transport_protocol=client.transport_protocol
        )
        self.layers = []
        self.extra = {}

    def fork(self) -> "Context":
        ret = Context(self.client, self.options)
        ret.server = self.server
        ret.layers = self.layers.copy()
        ret.extra = self.extra
        return ret

    def __repr__(self):
        return (
            f"Context(\n"
            f"  {self.client!r},\n"
            f"  {self.server!r},\n"
            f"  layers=[{self.layers!r}]\n"
            f")"
        )

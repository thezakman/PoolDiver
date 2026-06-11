"""ASCII banner rendering."""

from rich import box
from rich.align import Align
from rich.console import Group
from rich.panel import Panel
from rich.text import Text

from . import __version__
from .console import console

_BANNER = r"""
                    _
          dev-v{ver} | |
 _ __   ___   ___  | |
| '_ \ / _ \ / _ \ | |
| |A| | |W| | |S| || |
| |_| | |_| | |_| || |
| .__/ \___/ \___/ |_|
| |         ~~DIVER 🤿
|_|  HOW DEEP CAN I GO?
""".format(ver=__version__)


def print_banner() -> None:
    """Render the PoolDiver banner panel to the shared console."""
    art = Text(_BANNER, style="bold yellow")
    art.highlight_words(["A", "W", "S"], "bold cyan")
    subtitle = Text.assemble(
        ("AWS Cognito Identity Pool Tester", "bold white"),
        ("  •  ", "dim"),
        ("@TheZakMan", "bold blue"),
    )
    console.print(
        Panel(
            Group(Align.center(art), Align.center(subtitle)),
            box=box.DOUBLE,
            border_style="cyan",
            padding=(0, 4),
        )
    )

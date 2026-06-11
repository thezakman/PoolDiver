"""Original left-aligned ASCII banner."""

from rich.text import Text

from . import __version__
from .console import console

# Keep "| |" aligned with the rest of the art regardless of version length.
_VER_LINE = f"dev-v{__version__}".rjust(18) + " | |"

_ART = f"""\
                    _
{_VER_LINE}
 _ __   ___   ___  | |
| '_ \\ / _ \\ / _ \\ | |
| |A| | |W| | |S| || |
| |_| | |_| | |_| || |
| .__/ \\___/ \\___/ |_|
| |         ~~DIVER 🤿
|_| HOW DEEP CAN I GO?"""

_WAVES = (
    "⎼─–─⎼⎼─–─⎼⎼─–─⎼⎼─–─⎼⎼─–─⎼\n"
    "⎽⎼–⎻⎺⎺⎻–⎼⎽⎽⎼–⎻⎺⎺⎻–⎼⎽⎽⎼\n"
    "``'-.,_,.-'``'-.,_,.='\n"
    "-.,_,.='``'-.,_,.-'``'"
)


def print_banner() -> None:
    """Print the PoolDiver banner left-aligned to the shared console."""
    art = Text(_ART, style="yellow")
    art.highlight_words([f"dev-v{__version__}"], "white")
    art.highlight_words(["HOW DEEP CAN I GO?"], "white")
    console.print(art)
    console.print(Text(_WAVES, style="cyan"))
    console.print(Text("            @TheZakMan", style="bright_blue"))

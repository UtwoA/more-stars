import asyncio
import logging
import os
from typing import Optional, Union, List

from pyrogram import Client, raw, types, enums, utils
from pyrogram.errors import RPCError

logger = logging.getLogger("gifts")

_client: Client | None = None
_client_started = False
_client_lock = asyncio.Lock()


def _build_client() -> Client:
    api_id = os.getenv("PYROFORK_API_ID")
    api_hash = os.getenv("PYROFORK_API_HASH")
    if not api_id or not api_hash:
        raise RuntimeError("PYROFORK_API_ID/PYROFORK_API_HASH are not set")

    session_string = os.getenv("PYROFORK_SESSION_STRING")
    session_value = os.getenv("PYROFORK_SESSION", "example.session")
    workdir = os.getenv("PYROFORK_SESSION_DIR")

    if session_string:
        return Client(
            name=":memory:",
            api_id=int(api_id),
            api_hash=api_hash,
            session_string=session_string,
            workdir=workdir,
        )

    session_name = session_value
    if "/" in session_value or "\\" in session_value or session_value.endswith(".session"):
        dir_name, base_name = os.path.split(session_value)
        if base_name.endswith(".session"):
            base_name = base_name[:-8]
        session_name = base_name or "pyrofork"
        if dir_name:
            workdir = dir_name

    if not workdir:
        workdir = "/tmp/pyrofork_sessions"

    os.makedirs(workdir, exist_ok=True)

    return Client(
        name=session_name,
        api_id=int(api_id),
        api_hash=api_hash,
        workdir=workdir,
    )


async def _get_client() -> Client:
    global _client, _client_started
    async with _client_lock:
        if _client is None:
            _client = _build_client()
        if not _client_started:
            await _client.start()
            _client_started = True
    return _client


async def close_gift_client() -> None:
    global _client, _client_started
    async with _client_lock:
        if _client is not None and _client_started:
            await _client.stop()
        _client = None
        _client_started = False


async def send_star_gift(
    chat_id: Union[int, str],
    gift_id: int,
    text: Optional[str] = None,
    parse_mode: Optional["enums.ParseMode"] = None,
    entities: Optional[List["types.MessageEntity"]] = None,
    hide_my_name: Optional[bool] = None,
    pay_for_upgrade: Optional[bool] = None,
) -> bool:
    client = await _get_client()

    peer = await client.resolve_peer(chat_id)
    text, entities = (await utils.parse_text_entities(client, text, parse_mode, entities)).values()

    invoice = raw.types.InputInvoiceStarGift(
        peer=peer,
        gift_id=gift_id,
        hide_name=hide_my_name,
        include_upgrade=pay_for_upgrade,
        message=raw.types.TextWithEntities(text=text, entities=entities) if text else None,
    )

    try:
        form = await client.invoke(
            raw.functions.payments.GetPaymentForm(
                invoice=invoice,
            )
        )

        await client.invoke(
            raw.functions.payments.SendStarsForm(
                form_id=form.form_id,
                invoice=invoice,
            )
        )
    except RPCError as exc:
        msg = str(exc)
        if "PEER" in msg or "PEER_ID_INVALID" in msg or "USER_ID_INVALID" in msg:
            logger.warning("[GIFT] Peer invalid or inaccessible: %s", msg)
            raise RuntimeError(
                "PEER_INVALID: recipient is not accessible. "
                "Use @username or make sure the account has an existing chat/contact with the recipient."
            ) from exc
        raise

    return True

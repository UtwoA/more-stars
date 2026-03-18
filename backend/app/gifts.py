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

    proxy = _get_proxy()

    session_string = os.getenv("PYROFORK_SESSION_STRING")
    session_value = os.getenv("PYROFORK_SESSION", "example.session")
    workdir = os.getenv("PYROFORK_SESSION_DIR")

    no_updates = os.getenv("PYROFORK_NO_UPDATES", "true").strip().lower() in {"1", "true", "yes", "on"}

    if session_string:
        return Client(
            name=":memory:",
            api_id=int(api_id),
            api_hash=api_hash,
            session_string=session_string,
            workdir=workdir,
            proxy=proxy,
            no_updates=no_updates,
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

    if not session_string:
        session_path = os.path.join(workdir, f"{session_name}.session")
        if not os.path.isfile(session_path):
            raise RuntimeError(
                "Pyrogram session file not found. "
                "Put the .session file into PYROFORK_SESSION_DIR (or /tmp/pyrofork_sessions) "
                "and set PYROFORK_SESSION to its name/path."
            )

    return Client(
        name=session_name,
        api_id=int(api_id),
        api_hash=api_hash,
        workdir=workdir,
        proxy=proxy,
        no_updates=no_updates,
    )


def _get_proxy() -> dict | None:
    proxy_type = (os.getenv("PYROFORK_PROXY_TYPE") or "").strip().lower()
    if not proxy_type:
        return None

    host = (os.getenv("PYROFORK_PROXY_HOST") or "").strip()
    port_raw = (os.getenv("PYROFORK_PROXY_PORT") or "").strip()
    if not host or not port_raw:
        raise RuntimeError(
            "PYROFORK_PROXY_HOST/PYROFORK_PROXY_PORT are required when PYROFORK_PROXY_TYPE is set"
        )

    try:
        port = int(port_raw)
    except ValueError as exc:
        raise RuntimeError("PYROFORK_PROXY_PORT must be an integer") from exc

    proxy: dict = {
        "scheme": proxy_type,
        "hostname": host,
        "port": port,
    }

    if proxy_type == "mtproto":
        logger.warning(
            "MTProto proxy type is not supported by Pyrogram. Proxy will be ignored."
        )
        return None

    username = (os.getenv("PYROFORK_PROXY_USER") or "").strip()
    password = (os.getenv("PYROFORK_PROXY_PASSWORD") or "").strip()
    if username:
        proxy["username"] = username
    if password:
        proxy["password"] = password

    rdns_raw = (os.getenv("PYROFORK_PROXY_RDNS") or "").strip().lower()
    if rdns_raw in {"1", "true", "yes", "on"}:
        proxy["rdns"] = True
    elif rdns_raw in {"0", "false", "no", "off"}:
        proxy["rdns"] = False

    return proxy


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
    last_exc: Exception | None = None
    for attempt in range(1, 4):
        try:
            client = await _get_client()

            peer = await client.resolve_peer(chat_id)
            if text is None:
                text = ""
            text, entities = (await utils.parse_text_entities(client, text, parse_mode, entities)).values()
            if entities is None:
                entities = []

            invoice = raw.types.InputInvoiceStarGift(
                peer=peer,
                gift_id=gift_id,
                hide_name=hide_my_name,
                include_upgrade=pay_for_upgrade,
                message=raw.types.TextWithEntities(text=text, entities=entities) if text else None,
            )

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
            return True
        except RPCError as exc:
            msg = str(exc)
            if "PEER" in msg or "PEER_ID_INVALID" in msg or "USER_ID_INVALID" in msg:
                logger.warning("[GIFT] Peer invalid or inaccessible: %s", msg)
                raise RuntimeError(
                    "PEER_INVALID: recipient is not accessible. "
                    "Use @username or make sure the account has an existing chat/contact with the recipient."
                ) from exc
            last_exc = exc
        except (OSError, ConnectionResetError, asyncio.TimeoutError) as exc:
            last_exc = exc
            logger.warning("[GIFT] Network error (attempt %s/3): %s", attempt, exc)
            await close_gift_client()
            await asyncio.sleep(1.5 * attempt)
        except Exception as exc:
            last_exc = exc
            logger.warning("[GIFT] Unexpected error (attempt %s/3): %s", attempt, exc)
            await close_gift_client()
            await asyncio.sleep(1.5 * attempt)

    raise RuntimeError("TEMPORARY_NETWORK_ERROR: failed to send gift after retries") from last_exc

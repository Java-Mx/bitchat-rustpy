"""Phase 3 Mouse Navigation Stability & Bluetooth Settings Diagnostics Tests."""

from __future__ import annotations

import pytest
from textual.widgets import Static

from bitchat.app.session_coordinator import SessionCoordinator
from bitchat.crypto.identity import LocalIdentity
from bitchat.protocol.constants import (
    BITCHAT_CHARACTERISTIC_UUID,
    BITCHAT_SERVICE_UUID,
)
from bitchat.storage.config import AppConfig, InMemoryStorage
from bitchat.tui.app import BitChatApp
from bitchat.tui.screens.edit_theme import EditThemeModal
from bitchat.tui.screens.help import HelpScreen
from bitchat.tui.screens.peers import PeersScreen
from bitchat.tui.screens.settings import SettingsScreen


def _make_test_app() -> BitChatApp:
    identity = LocalIdentity.generate()
    storage = InMemoryStorage()
    config = AppConfig(nickname="Phase3User", transport="offline")
    storage.save_config(config)
    coordinator = SessionCoordinator(
        local_identity=identity,
        storage=storage,
        nickname="Phase3User",
        initial_transport="offline",
    )
    coordinator.offline_mode = True
    return BitChatApp(
        coordinator=coordinator,
        config=config,
        storage=storage,
        initial_screen="chat",
    )


@pytest.mark.asyncio
async def test_single_mouse_click_on_status_bar_opens_settings_exactly_once() -> None:
    """Clicking Settings once in StatusBar must push SettingsScreen ONCE (no triple-fire jitter)."""
    app = _make_test_app()
    open_calls = 0
    orig_open_settings = app.action_open_settings

    def tracked_open_settings(*args: object, **kwargs: object) -> None:
        nonlocal open_calls
        open_calls += 1
        orig_open_settings(*args, **kwargs)  # type: ignore[arg-type]

    app.action_open_settings = tracked_open_settings  # type: ignore[method-assign]

    async with app.run_test(size=(140, 42)) as pilot:
        await pilot.pause()
        assert len(app._screen_stack) == 1

        await pilot.click("#btn-action-settings")
        await pilot.pause()

        assert open_calls == 1, f"Expected 1 call on single click, got {open_calls}"
        assert isinstance(app.screen, SettingsScreen)
        assert len(app._screen_stack) == 2

        # Close via Back button -> single clean return to Chat
        await pilot.click("#btn-settings-cancel")
        await pilot.pause()
        assert len(app._screen_stack) == 1
        assert not isinstance(app.screen, SettingsScreen)


@pytest.mark.asyncio
async def test_mouse_clicks_across_status_bar_buttons_no_jitter_or_duplicate_modals() -> (
    None
):
    """Mouse clicks on Edit, Peers, Help, and Settings must each execute once cleanly."""
    app = _make_test_app()

    async with app.run_test(size=(140, 42)) as pilot:
        await pilot.pause()
        base_depth = len(app._screen_stack)

        # 1. Edit Theme modal -> Cancel
        await pilot.click("#btn-action-edit")
        await pilot.pause()
        assert isinstance(app.screen, EditThemeModal)
        assert len(app._screen_stack) == base_depth + 1
        await pilot.click("#btn-theme-close")
        await pilot.pause()
        assert len(app._screen_stack) == base_depth

        # 2. Help modal -> Close
        await pilot.click("#btn-action-help")
        await pilot.pause()
        assert isinstance(app.screen, HelpScreen)
        assert len(app._screen_stack) == base_depth + 1
        await pilot.click("#help-close-btn")
        await pilot.pause()
        assert len(app._screen_stack) == base_depth

        # 3. Peers screen -> Back
        await pilot.click("#btn-action-peers")
        await pilot.pause()
        assert isinstance(app.screen, PeersScreen)
        assert len(app._screen_stack) == base_depth + 1
        await pilot.click("#btn-peers-back")
        await pilot.pause()
        assert len(app._screen_stack) == base_depth


@pytest.mark.asyncio
async def test_settings_category_switching_via_mouse_and_truthful_bluetooth_diagnostics() -> (
    None
):
    """Bluetooth Settings tab displays canonical UUIDs, zero blank boxes, and truthful telemetry."""
    app = _make_test_app()

    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        await pilot.click("#btn-action-settings")
        await pilot.pause()
        assert isinstance(app.screen, SettingsScreen)

        # Click Bluetooth category button
        await pilot.click("#btn-cat-bluetooth")
        await pilot.pause(0.25)

        screen = app.screen
        assert isinstance(screen, SettingsScreen)
        assert screen.active_category == "bluetooth"

        uuid_text = str(screen.query_one("#settings-static-ble-uuid", Static).render())
        char_text = str(
            screen.query_one("#settings-static-ble-char-uuid", Static).render()
        )
        assert BITCHAT_SERVICE_UUID.upper() in uuid_text.upper()
        assert "0000fee0" not in uuid_text.lower()
        assert BITCHAT_CHARACTERISTIC_UUID.upper() in char_text.upper()

        # Verify ZERO blank boxes across all Bluetooth diagnostic fields
        bt_selectors = (
            "#settings-static-ble-backend",
            "#settings-static-ble-adapter",
            "#settings-static-ble-radio",
            "#settings-static-ble-uuid",
            "#settings-static-ble-char-uuid",
            "#settings-static-ble-peripheral",
            "#settings-static-ble-gatt-status",
            "#settings-static-ble-adv-status",
            "#settings-static-ble-central",
            "#settings-static-ble-peers",
            "#settings-static-ble-error",
            "#settings-static-ble-refresh",
        )
        for sel in bt_selectors:
            rendered = str(screen.query_one(sel, Static).render()).strip()
            assert rendered, f"Bluetooth diagnostic field {sel} must not be blank!"

        # Central role must NOT falsely claim 'Active / Scanning' when offline/stopped
        central_text = str(
            screen.query_one("#settings-static-ble-central", Static).render()
        )
        assert "Active / Scanning" not in central_text

        # Click Refresh Bluetooth Information button without crashing or flickering
        refresh_btn = screen.query_one("#btn-settings-bluetooth-refresh")
        refresh_btn.scroll_visible(animate=False)
        await pilot.pause(0.1)
        await pilot.click("#btn-settings-bluetooth-refresh")
        await pilot.pause(0.2)
        assert screen.active_category == "bluetooth"

        # Switch to Network tab -> Wi-Fi / Network diagnostics remain intact!
        await pilot.click("#btn-cat-network")
        await pilot.pause(0.1)
        assert screen.active_category == "network"
        net_conn = str(
            screen.query_one("#settings-network-connection", Static).render()
        ).strip()
        assert net_conn

        # Switch across other categories rapidly without crashing
        for cat in ("general", "identity", "notifications", "appearance", "advanced"):
            await pilot.click(f"#btn-cat-{cat}")
            await pilot.pause(0.05)
            assert screen.active_category == cat

        await pilot.click("#btn-settings-cancel")
        await pilot.pause()
        assert len(app._screen_stack) == 1

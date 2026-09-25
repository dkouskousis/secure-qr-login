"""Config and options flow for Secure QR Login."""

from __future__ import annotations

import probatio

from homeassistant import config_entries
from homeassistant.helpers import selector

from .const import (
    CONF_ALLOWED_USER_IDS,
    CONF_ENABLE_WINDOW_SECONDS,
    CONF_HISTORY_LIMIT,
    CONF_MAX_PENDING_SESSIONS,
    CONF_NOTIFY_ON_APPROVED,
    CONF_NOTIFY_ON_DENIED,
    CONF_NOTIFY_SERVICES,
    CONF_QR_LIFETIME_SECONDS,
    DEFAULT_ALLOWED_USER_IDS,
    DEFAULT_ENABLE_WINDOW_SECONDS,
    DEFAULT_HISTORY_LIMIT,
    DEFAULT_MAX_PENDING_SESSIONS,
    DEFAULT_NOTIFY_ON_APPROVED,
    DEFAULT_NOTIFY_ON_DENIED,
    DEFAULT_NOTIFY_SERVICES,
    DEFAULT_QR_LIFETIME_SECONDS,
    DOMAIN,
    MAX_ENABLE_WINDOW_SECONDS,
    MAX_HISTORY_LIMIT,
    MAX_MAX_PENDING_SESSIONS,
    MAX_QR_LIFETIME_SECONDS,
    MIN_ENABLE_WINDOW_SECONDS,
    MIN_HISTORY_LIMIT,
    MIN_MAX_PENDING_SESSIONS,
    MIN_QR_LIFETIME_SECONDS,
    NAME,
)


class SecureQrLoginConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Create the single Secure QR Login config entry."""

    VERSION = 1

    async def async_step_user(self, user_input=None):
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()
        if user_input is not None:
            return self.async_create_entry(title=NAME, data={})
        return self.async_show_form(step_id="user")

    @staticmethod
    def async_get_options_flow(config_entry):
        """Return the options flow."""
        return SecureQrLoginOptionsFlow()


class SecureQrLoginOptionsFlow(config_entries.OptionsFlow):
    """Security-focused configurable settings."""

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(
                title="",
                data=self.config_entry.options | user_input,
            )

        # Only active, human users are eligible for QR approval.
        users = await self.hass.auth.async_get_users()
        user_options = [
            {"value": user.id, "label": user.name or user.id}
            for user in users
            if user.is_active and not user.system_generated
        ]

        notify_domain = self.hass.services.async_services().get("notify", {})
        notify_options = [
            {"value": service, "label": f"notify.{service}"}
            for service in sorted(notify_domain)
        ]

        options = self.config_entry.options
        return self.async_show_form(
            step_id="init",
            data_schema=probatio.Schema(
                {
                    probatio.Required(
                        CONF_ENABLE_WINDOW_SECONDS,
                        default=options.get(
                            CONF_ENABLE_WINDOW_SECONDS,
                            DEFAULT_ENABLE_WINDOW_SECONDS,
                        ),
                    ): selector.NumberSelector(
                        selector.NumberSelectorConfig(
                            min=MIN_ENABLE_WINDOW_SECONDS,
                            max=MAX_ENABLE_WINDOW_SECONDS,
                            step=10,
                            mode=selector.NumberSelectorMode.BOX,
                        )
                    ),
                    probatio.Required(
                        CONF_QR_LIFETIME_SECONDS,
                        default=options.get(
                            CONF_QR_LIFETIME_SECONDS,
                            DEFAULT_QR_LIFETIME_SECONDS,
                        ),
                    ): selector.NumberSelector(
                        selector.NumberSelectorConfig(
                            min=MIN_QR_LIFETIME_SECONDS,
                            max=MAX_QR_LIFETIME_SECONDS,
                            step=1,
                            mode=selector.NumberSelectorMode.BOX,
                        )
                    ),
                    probatio.Required(
                        CONF_MAX_PENDING_SESSIONS,
                        default=options.get(
                            CONF_MAX_PENDING_SESSIONS,
                            DEFAULT_MAX_PENDING_SESSIONS,
                        ),
                    ): selector.NumberSelector(
                        selector.NumberSelectorConfig(
                            min=MIN_MAX_PENDING_SESSIONS,
                            max=MAX_MAX_PENDING_SESSIONS,
                            step=1,
                            mode=selector.NumberSelectorMode.BOX,
                        )
                    ),
                    probatio.Required(
                        CONF_HISTORY_LIMIT,
                        default=options.get(CONF_HISTORY_LIMIT, DEFAULT_HISTORY_LIMIT),
                    ): selector.NumberSelector(
                        selector.NumberSelectorConfig(
                            min=MIN_HISTORY_LIMIT,
                            max=MAX_HISTORY_LIMIT,
                            step=10,
                            mode=selector.NumberSelectorMode.BOX,
                        )
                    ),
                    probatio.Optional(
                        CONF_ALLOWED_USER_IDS,
                        default=options.get(
                            CONF_ALLOWED_USER_IDS,
                            DEFAULT_ALLOWED_USER_IDS,
                        ),
                    ): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=user_options,
                            multiple=True,
                            mode=selector.SelectSelectorMode.DROPDOWN,
                        )
                    ),
                    probatio.Optional(
                        CONF_NOTIFY_SERVICES,
                        default=options.get(
                            CONF_NOTIFY_SERVICES,
                            DEFAULT_NOTIFY_SERVICES,
                        ),
                    ): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=notify_options,
                            multiple=True,
                            mode=selector.SelectSelectorMode.DROPDOWN,
                        )
                    ),
                    probatio.Required(
                        CONF_NOTIFY_ON_APPROVED,
                        default=options.get(
                            CONF_NOTIFY_ON_APPROVED,
                            DEFAULT_NOTIFY_ON_APPROVED,
                        ),
                    ): selector.BooleanSelector(),
                    probatio.Required(
                        CONF_NOTIFY_ON_DENIED,
                        default=options.get(
                            CONF_NOTIFY_ON_DENIED,
                            DEFAULT_NOTIFY_ON_DENIED,
                        ),
                    ): selector.BooleanSelector(),
                }
            ),
        )

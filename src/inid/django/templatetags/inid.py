"""{% load inid %} {% inid_sign_in app_name="Mi App" return_to="/panel" %}"""

from __future__ import annotations

from typing import Any

from django import template
from django.utils.html import escape, format_html, format_html_join
from django.utils.safestring import SafeString

from inid import INID_JS_URL

register = template.Library()


@register.simple_tag
def inid_script() -> SafeString:
    """The @inid/js browser components (<inid-sign-in>, <inid-user-button>, ...)."""
    return format_html('<script src="{}" defer></script>', INID_JS_URL)


@register.simple_tag
def inid_sign_in(script: bool = True, **attributes: Any) -> SafeString:
    """InID's sign-in form in the page. Keyword arguments become attributes: app_name ->
    app-name, return_to, entrance, redirect, api_path, locale. True renders a bare attribute."""
    attrs = []
    for key, value in attributes.items():
        if value is None or value is False:
            continue
        # Always escaped: template string literals arrive marked safe
        attrs.append((key.replace("_", "-"), escape("" if value is True else str(value))))
    rendered = format_html_join("", ' {}="{}"', attrs)
    element = format_html("<inid-sign-in{}></inid-sign-in>", rendered)
    return format_html("{}{}", inid_script() if script else "", element)

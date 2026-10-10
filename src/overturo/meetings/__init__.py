"""Meetings — the organisation's side of meeting consent (window, platform,
cancellation, participants with their decisions). See :mod:`.client`."""

from .client import (
    cancel_meeting,
    cancel_meeting_async,
    create_meeting,
    create_meeting_async,
    list_meetings,
    list_meetings_async,
    list_participants,
    list_participants_async,
    retrieve_meeting,
    retrieve_meeting_async,
    update_meeting,
    update_meeting_async,
)

__all__ = [
    "cancel_meeting",
    "cancel_meeting_async",
    "create_meeting",
    "create_meeting_async",
    "list_meetings",
    "list_meetings_async",
    "list_participants",
    "list_participants_async",
    "retrieve_meeting",
    "retrieve_meeting_async",
    "update_meeting",
    "update_meeting_async",
]

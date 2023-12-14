# Okta intel module - sync state
from typing import List
from typing import Optional


class OktaSyncState:
    """
    Okta sync state.
    Object used to store sync data to allow each stages to share data. For example, saving user and group list returned
    by Okta instead of asking the Graph for factor and role stages.
    :type users: array of string
    :param users: Array of user id as string. Optional.
    :type groups: array of string
    :param groups: Array of group id as string. Optional
    """

    def __init__(
        self,
        user: Optional[List[str]] = None,
        groups: Optional[List[str]] = None,
    ) -> None:
        self.users = user
        self.groups = groups

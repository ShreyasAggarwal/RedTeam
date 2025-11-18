"""
Access Control and Role-Based Permissions system.
"""

import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set
from enum import Enum


class Role(Enum):
    """User roles with different permission levels."""
    ADMIN = "admin"
    OPERATOR = "operator"
    ANALYST = "analyst"
    READ_ONLY = "read_only"


class Permission(Enum):
    """Available permissions in the system."""
    # Attack operations
    RUN_ATTACKS = "run_attacks"
    CREATE_ATTACKS = "create_attacks"
    DELETE_ATTACKS = "delete_attacks"

    # Data access
    VIEW_RESULTS = "view_results"
    EXPORT_DATA = "export_data"
    DELETE_DATA = "delete_data"

    # Model operations
    QUERY_MODELS = "query_models"
    CONFIGURE_MODELS = "configure_models"

    # System operations
    VIEW_AUDIT_LOG = "view_audit_log"
    MANAGE_USERS = "manage_users"
    CONFIGURE_SYSTEM = "configure_system"

    # Security operations
    SCAN_PII = "scan_pii"
    SCAN_CREDENTIALS = "scan_credentials"


# Role to permissions mapping
ROLE_PERMISSIONS = {
    Role.ADMIN: [
        Permission.RUN_ATTACKS,
        Permission.CREATE_ATTACKS,
        Permission.DELETE_ATTACKS,
        Permission.VIEW_RESULTS,
        Permission.EXPORT_DATA,
        Permission.DELETE_DATA,
        Permission.QUERY_MODELS,
        Permission.CONFIGURE_MODELS,
        Permission.VIEW_AUDIT_LOG,
        Permission.MANAGE_USERS,
        Permission.CONFIGURE_SYSTEM,
        Permission.SCAN_PII,
        Permission.SCAN_CREDENTIALS,
    ],
    Role.OPERATOR: [
        Permission.RUN_ATTACKS,
        Permission.CREATE_ATTACKS,
        Permission.VIEW_RESULTS,
        Permission.EXPORT_DATA,
        Permission.QUERY_MODELS,
        Permission.SCAN_PII,
        Permission.SCAN_CREDENTIALS,
    ],
    Role.ANALYST: [
        Permission.VIEW_RESULTS,
        Permission.EXPORT_DATA,
        Permission.VIEW_AUDIT_LOG,
        Permission.SCAN_PII,
        Permission.SCAN_CREDENTIALS,
    ],
    Role.READ_ONLY: [
        Permission.VIEW_RESULTS,
    ],
}


class User:
    """Represents a user in the system."""

    def __init__(self, username: str, role: Role, email: Optional[str] = None):
        """
        Initialize user.

        Args:
            username: Unique username
            role: User role
            email: Optional email address
        """
        self.username = username
        self.role = role
        self.email = email
        self.permissions = set(ROLE_PERMISSIONS[role])

    def has_permission(self, permission: Permission) -> bool:
        """
        Check if user has a specific permission.

        Args:
            permission: Permission to check

        Returns:
            True if user has permission
        """
        return permission in self.permissions

    def to_dict(self) -> Dict:
        """Convert user to dictionary."""
        return {
            'username': self.username,
            'role': self.role.value,
            'email': self.email,
            'permissions': [p.value for p in self.permissions]
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'User':
        """Create user from dictionary."""
        return cls(
            username=data['username'],
            role=Role(data['role']),
            email=data.get('email')
        )


class AccessControl:
    """Access control system managing users and permissions."""

    def __init__(self, users_file: str = "data/users.json"):
        """
        Initialize access control.

        Args:
            users_file: Path to users configuration file
        """
        self.users_file = Path(users_file)
        self.users: Dict[str, User] = {}
        self._load_users()

        # Create default admin if no users exist
        if not self.users:
            self._create_default_admin()

    def _load_users(self):
        """Load users from file."""
        if self.users_file.exists():
            try:
                with open(self.users_file, 'r') as f:
                    data = json.load(f)
                    self.users = {
                        username: User.from_dict(user_data)
                        for username, user_data in data.items()
                    }
            except Exception as e:
                print(f"Warning: Could not load users file: {e}")

    def _save_users(self):
        """Save users to file."""
        self.users_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.users_file, 'w') as f:
            data = {
                username: user.to_dict()
                for username, user in self.users.items()
            }
            json.dump(data, f, indent=2)

    def _create_default_admin(self):
        """Create default admin user."""
        admin = User("admin", Role.ADMIN, "admin@localhost")
        self.users["admin"] = admin
        self._save_users()

    def add_user(self, username: str, role: Role, email: Optional[str] = None) -> User:
        """
        Add a new user.

        Args:
            username: Unique username
            role: User role
            email: Optional email

        Returns:
            Created user

        Raises:
            ValueError: If username already exists
        """
        if username in self.users:
            raise ValueError(f"User {username} already exists")

        user = User(username, role, email)
        self.users[username] = user
        self._save_users()
        return user

    def remove_user(self, username: str):
        """
        Remove a user.

        Args:
            username: Username to remove

        Raises:
            ValueError: If user doesn't exist or is last admin
        """
        if username not in self.users:
            raise ValueError(f"User {username} does not exist")

        # Prevent removing last admin
        if self.users[username].role == Role.ADMIN:
            admin_count = sum(1 for u in self.users.values() if u.role == Role.ADMIN)
            if admin_count <= 1:
                raise ValueError("Cannot remove the last admin user")

        del self.users[username]
        self._save_users()

    def get_user(self, username: str) -> Optional[User]:
        """
        Get user by username.

        Args:
            username: Username to lookup

        Returns:
            User or None if not found
        """
        return self.users.get(username)

    def update_user_role(self, username: str, new_role: Role):
        """
        Update user's role.

        Args:
            username: Username to update
            new_role: New role

        Raises:
            ValueError: If user doesn't exist or last admin being demoted
        """
        if username not in self.users:
            raise ValueError(f"User {username} does not exist")

        user = self.users[username]
        old_role = user.role

        # Prevent demoting last admin
        if old_role == Role.ADMIN and new_role != Role.ADMIN:
            admin_count = sum(1 for u in self.users.values() if u.role == Role.ADMIN)
            if admin_count <= 1:
                raise ValueError("Cannot demote the last admin user")

        user.role = new_role
        user.permissions = set(ROLE_PERMISSIONS[new_role])
        self._save_users()

    def check_permission(self, username: str, permission: Permission) -> bool:
        """
        Check if user has permission.

        Args:
            username: Username to check
            permission: Permission to verify

        Returns:
            True if user has permission

        Raises:
            ValueError: If user doesn't exist
        """
        user = self.get_user(username)
        if not user:
            raise ValueError(f"User {username} does not exist")

        return user.has_permission(permission)

    def require_permission(self, username: str, permission: Permission):
        """
        Require user to have permission.

        Args:
            username: Username to check
            permission: Required permission

        Raises:
            PermissionError: If user lacks permission
            ValueError: If user doesn't exist
        """
        if not self.check_permission(username, permission):
            raise PermissionError(
                f"User {username} does not have permission: {permission.value}"
            )

    def list_users(self) -> List[Dict]:
        """
        List all users.

        Returns:
            List of user dictionaries
        """
        return [user.to_dict() for user in self.users.values()]

    def get_user_permissions(self, username: str) -> List[str]:
        """
        Get list of user's permissions.

        Args:
            username: Username to check

        Returns:
            List of permission names

        Raises:
            ValueError: If user doesn't exist
        """
        user = self.get_user(username)
        if not user:
            raise ValueError(f"User {username} does not exist")

        return [p.value for p in user.permissions]


# Global access control instance
_access_control = None


def get_access_control(users_file: str = "data/users.json") -> AccessControl:
    """
    Get or create the global access control instance.

    Args:
        users_file: Path to users configuration file

    Returns:
        AccessControl instance
    """
    global _access_control
    if _access_control is None:
        _access_control = AccessControl(users_file)
    return _access_control


def require_permission(permission: Permission):
    """
    Decorator to require permission for a function.

    Args:
        permission: Required permission

    Returns:
        Decorator function
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Try to get username from kwargs
            username = kwargs.get('user', 'admin')
            ac = get_access_control()
            ac.require_permission(username, permission)
            return func(*args, **kwargs)
        return wrapper
    return decorator

from marshmallow_jsonapi import fields
from marshmallow_jsonapi.flask import Schema


# User object serialization schema class
class UserSchema(Schema):
    id = fields.Str(dump_only=True)

    class Meta:
        type_ = "users"
        strict = True
        self_view = "auth.get_user"
        self_view_kwargs = {"id": "<id>"}
        self_view_many = "auth.get_all_user"

        # Fields to expose
        fields = ("id", "username", "fullname_value", "address",
                  "contact", "is_admin", "created_on_value")

from marshmallow_jsonapi import fields
from marshmallow_jsonapi.flask import Schema


# Order object serialization schema class
class OrderSchema(Schema):
    id = fields.Str(dump_only=True)

    class Meta:
        type_ = "orders"
        strict = True
        self_view = "billing.get_order"
        self_view_kwargs = {"user_id": "<user_id>", "order_id": "<id>"}

        # Fields to expose
        fields = ("id", "service", "url", "date_value",
                  "approval_date_value", "approver_id", "user_id",
                  "status_value", "approval_status_value")

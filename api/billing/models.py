import datetime
from flask import current_app
from sqlalchemy import Sequence, text, exc
from marshmallow_jsonapi import fields
from marshmallow_jsonapi.flask import Schema

from api import db


# Order status
status = ['Not Active', 'Active']

# Order approval
approval = ['Cancelled', 'Pending', 'Approved']


# Get the id sequence value to be used based from data center location
sequence = current_app.config['DC_SEQ_DEFAULT']
sql = text('SELECT current_id_sequence FROM location WHERE name = :param;')
result = db.session.execute(sql,
                            {"param": current_app.config['DC_LOCATION']})

# Get ResultProxy object
if result:
    # Get RowProxy object
    row = result.first()
    if row:
        sequence = row['current_id_sequence']


TABLE_ID = Sequence('orders_id_seq', start=sequence)

# Order model class
class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.BigInteger, TABLE_ID, primary_key=True,
                   server_default=TABLE_ID.next_value())
    service = db.Column(db.String(255), index=True)
    status = db.Column(db.SmallInteger)
    approval_status = db.Column(db.SmallInteger)
    url = db.Column(db.String(255))
    date = db.Column(db.DateTime(timezone=True),
                     default=datetime.datetime.now)
    approval_date = db.Column(db.DateTime(timezone=True))
    approver_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer)

    @property
    def date_value(self):
        return self.date.strftime("%Y-%m-%d %H:%M:%S %z")

    @property
    def approval_date_value(self):
        if self.approval_date is None:
            return ''
        return self.approval_date.strftime("%Y-%m-%d %H:%M:%S %z")

    @property
    def status_value(self):
        return status[self.status]

    @property
    def approval_status_value(self):
        return approval[self.approval_status]


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

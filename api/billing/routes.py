import datetime
from flask import current_app, request, jsonify

from api import db
from api.billing import bp
from api.billing.models import Order, status, approval
from api.billing.schemas import OrderSchema
from api.error.handlers import bad_request, not_found, duplicate


# Register a function to be run at the end of each request,
# regardless of whether there was an exception or not
@bp.teardown_request
def teardown_request(exception):
    if exception:
        db.session.rollback()
    db.session.remove()


# Order placement
# Requires token authentication
# Default Order Status: Not Active
# Default Approval Status: Pending for Approval
@bp.route('/api/users/<int:user_id>/orders/new', methods=['POST'])
@current_app.validate('order', 'order')
def new_order(user_id):
    # Check the request arguments
    service = request.json.get('service')
    url = request.json.get('url')

    # Check if order with same service name
    if Order.query.filter_by(service=service,
                             user_id=user_id).first() is not None:
        return duplicate('Service already exists')

    order = Order(service=service, url=url,
                  status=status.index('Not Active'),
                  approval_status=approval.index('Pending'),
                  user_id=user_id)
    db.session.add(order)
    db.session.commit()
    return (jsonify(OrderSchema().dump(order)), 201)


# Retrieve specific order for current user
# Requires token authentication
@bp.route('/api/users/<int:user_id>/orders/<int:order_id>',
            methods=['GET'])
def get_order(user_id, order_id):
    orders = Order.query.filter_by(id=order_id,
                                   user_id=user_id).one_or_none()
    return OrderSchema().dump(orders)


# Retrieve list of orders for current user
# Requires token authentication
@bp.route('/api/users/<int:user_id>/orders', methods=['GET'])
def get_order_list(user_id):
    orders = Order.query.filter_by(user_id=user_id).all()
    return OrderSchema(many=True).dump(orders)


# Delete/cancel order
# Requires token authentication
@bp.route('/api/users/<int:user_id>/orders/<int:order_id>',
            methods=['DELETE'])
def remove_order(user_id, order_id):
    # Filter by order id, user id, not active status
    order = Order.query.filter_by(id=order_id,
                                  user_id=user_id,
                                  status = status.index('Not Active')
                                  ).one_or_none()
    if not order:
        return not_found('Order not found')

    # Delete order
    db.session.delete(order)
    db.session.commit()
    orders = Order.query.filter_by(user_id=user_id).all()
    return OrderSchema(many=True).dump(orders)


# Approve or cancel pending order
# Requires token authentication
# Requires admin action
@bp.route('/api/admin/orders/<int:order_id>', methods=['PUT'])
@current_app.validate('admin', 'admin')
def update_order(order_id):
    # Filter by order id
    order = Order.query.filter_by(id=order_id).one_or_none()
    if not order:
        return not_found('Order not found')

    # Update order details
    action = request.json.get('action')
    if action.lower() == 'approved':
        order.approval_status = approval.index('Approved')
        order.status = status.index('Active')
    elif action.lower() == 'cancelled':
        order.approval_status = approval.index('Cancelled')
        order.status = status.index('Not Active')
    else:
        return bad_request('Invalid action')
    order.approver_id = request.json.get('approver_id')
    order.approval_date = datetime.datetime.now()
    db.session.commit()
    return OrderSchema().dump(order)


# Retrieve pending order list
# Requires token authentication
# Requires admin action
@bp.route('/api/admin/orders', methods=['GET'])
def get_pending_order():
    # Filter by approval status pending
    orders = Order.query.filter_by(
                   approval_status=approval.index('Pending')).all()
    return OrderSchema(many=True).dump(orders)

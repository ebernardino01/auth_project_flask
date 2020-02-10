API Documentation
=================

Gateway Microservice Public API
-------------------------------

- POST **/api/users/new**
    Register a new user.

- PUT **/auth**
    Returns an authentication token.

- POST **/orders/new**
    Creates a new order.

- GET **/orders**
    Returns all existing orders for the requesting user.

- DELETE **/orders/&lt;int:order_id&gt;**
    Removes an existing order for the requesting user.

- PUT **/admin/orders/&lt;int:order_id&gt;**
    Updates orders with pending status to approved or cancelled.

- GET **/admin/orders/**
    Returns all orders pending for admin approval.


Authentication Microservice Private API
---------------------------------------

- POST **/api/users/new**
    Register a new user.<br>
    The request body must contain a JSON object that defines the details of the new user.<br>
    On success, status code 201 is returned. Body of the response contains a JSON API 1.0 format object with the newly added user details.<br>
    On failure, status code 400 (bad request) or 409 (duplicate) is returned.
    
    Notes:
    - The username and password fields are required. Password is hashed before it is stored in the database.
    - Other details (firstname, lastname, address, contact) are optional. 
    - By default, user is non-admin. If the new user is admin, this should be specified.
   
- GET **/api/users/&lt;int:id&gt;**
    Returns an existing user.<br>
    On success, standard status code 200 is returned. Body of the response contains a JSON object with the requested user details.<br>
    On failure, status code 400 (bad request) or 404 (not found) is returned.

- GET **/api/users**
    Returns all existing users.<br>
    On success, standard status code 200 is returned. Body of the response contains a JSON object with the user details.<br>
    On failure, status code 400 (bad request) or 404 (not found) is returned.

- PUT **/api/auth**
    Returns an authentication token.<br>
    This request checks the provided username and password details.<br>
    On success, a JSON object with the authentication token for the requesting user is returned.<br>
    On failure, status code 400 (bad request) is returned.

- GET **/api/resource**
    Return a protected resource.<br>
    This request checks the provided authentication token.<br>
    On success, a JSON object with details of the authenticated user is returned.<br>
    On failure, status code 400 (bad request) is returned.


Billing Microservice Private API
--------------------------------

- POST **/api/users/&lt;int:user_id&gt;/orders/new**
    Creates a new order.<br>
    Request body must contain a JSON object that defines the details of the new order.<br>
    On success, status code 201 is returned. Body of the response contains a JSON API 1.0 format object with the newly added order details.<br>
    On failure, status code 400 (bad request) or 409 (duplicate) is returned.
    
    Notes:
    - The service name and service url fields are required.
    - By default, order status is not active, and pending for admin approval.

- GET **/api/users/&lt;int:user_id&gt;/orders/&lt;int:order_id&gt;**
    Returns an existing order for the requesting user.<br>
    On success, standard status code 200 is returned. Body of the response contains a JSON object with the requested order details.<br>
    On failure, status code 400 (bad request) is returned.

- GET **/api/users/&lt;int:user_id&gt;/orders**
    Returns all existing orders for the requesting user.<br>
    On success, standard status code 200 is returned. Body of the response contains a JSON object with the order details.<br>
    On failure, status code 400 (bad request) is returned.

- DELETE **/api/users/&lt;int:user_id&gt;/orders/&lt;int:order_id&gt;**
    Removes an existing order for the requesting user.<br>
    On success, standard status code 200 is returned. Body of the response contains a JSON object with the remaining orders and details.<br>
    On failure, status code 400 (bad request) or 404 (not found) is returned.

- GET **/api/admin/orders**
    Returns all orders pending for admin approval.<br>
    On success, standard status code 200 is returned. Body of the response contains a JSON object with the order details.<br>
    On failure, status code 400 (bad request) is returned.

- PUT **/api/admin/orders/&lt;int:order_id&gt;**
    Updates orders with pending status to approved or cancelled.<br>
    On success, standard status code 200 is returned. Body of the response contains a JSON object with the remaining pending orders and details.<br>
    On failure, status code 400 (bad request) or 404 (not found) is returned.

    Notes:
    - The order becomes active when action is approved. In opposite, it becomes inactive when cancelled.

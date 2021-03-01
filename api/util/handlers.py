from __future__ import division
from six.moves.urllib.parse import urlencode
from math import ceil
from copy import copy

import json
import datetime

from flask import current_app
from api.error.handlers import ApiException


jsonapi_headers = {'Content-Type': 'application/vnd.api+json'}
MANAGED_KEYS = (
    'filter',
    'page',
    'fields',
    'sort',
    'include',
    'q'
)


def split_by_separator(s):
    return [v for v in s.split(",") if v]


def simple_filters(collection):
    """Handler for simple filter condition"""

    return [{"name": key, "op": "eq", "val": value}
            for (key, value) in collection.items()]


def get_managed_keys(args):
    """Get original request args containing only managed keys"""

    return {key: value for (key, value) in args.items()
            if key.startswith(MANAGED_KEYS) or get_url_key_values('filter[')}


def get_url_key_values(name, args):
    """Obtain key/value pairs from given request argument"""

    results = {}
    # print("request args: {}".format(str(args.items())))
    for key, value in args.items():
        try:
            if not key.startswith(name):
                continue

            key_start = key.index('[') + 1
            key_end = key.index(']')
            item_key = key[key_start:key_end]
            item_value = value.split(',') if ',' in value else value
            results.update({item_key: item_value})
        except Exception:
            return None

    return results


def get_operator(column, op):
    """Obtain sqlalchemy operator info"""

    operators = (op, op + '_', '__' + op + '__')
    # print("operators: {}".format(str(operators)))
    for opr in operators:
        if hasattr(column, opr):
            return opr

    raise Exception("{} has no operator '{}'".format(column.key, op))


def get_column(model, name):
    """Obtain sqlalchemy column info from model"""

    column = getattr(model, name)
    # print("column: {}".format(str(column)))
    if column is None:
        raise Exception("{} object has no attribute [{}]".format(
            model.__name__, name))

    return column


def get_filters(args):
    """Obtain filtering info from request arguments"""

    filters = []
    results = args.get('filter')
    # print("results: {}".format(str(results)))
    if results:
        try:
            filters.extend(json.loads(results))
        except (ValueError, TypeError):
            raise ApiException("Error in parsing filter parameters")

    if get_url_key_values('filter[', args):
        filters.extend(simple_filters(get_url_key_values('filter[', args)))
    # print("filters: {}".format(str(filters)))

    return filters


def get_sorting(args):
    """Obtain sorting info from request arguments"""

    sorting = []
    results = args.get('sort')
    # print("results: {}".format(str(results)))
    if results:
        for sort_field in results.split(','):
            field = sort_field.replace('-', '')
            order = 'desc' if sort_field.startswith('-') else 'asc'
            sorting.append({'field': field, 'order': order})
    # print("sorting: {}".format(str(sorting)))

    return sorting


def get_pagination(args):
    """Obtain pagination info from request arguments"""

    results = get_url_key_values('page', args)
    # print("results: {}".format(str(results)))
    if results:
        for key, value in results.items():
            if key not in ('number', 'size'):
                raise ApiException(
                    "{} is not a valid parameter of pagination".format(key))
            try:
                int(value)
            except ValueError:
                raise ApiException("Error in parsing pagination parameters")

    return results


def create_query_conditions(session_query, model, args):
    """Custom query builder for filtering, sorting and pagination

    :param object session_query: sqlalchemy query object
    :param object model: sqlalchemy object instance
    :param dict args: request arguments
    """

    query = session_query
    conditions = []

    # Handle filter query conditions
    filters = get_filters(args)
    if filters:
        for filter in filters:
            try:
                value = filter['val']
                op = filter['op']
                # print("value: {}".format(str(value)))

                # Get column name object from model
                column = get_column(model, filter['name'])
                if isinstance(value, list):
                    # Change default operator to 'in' if value is list
                    operator = get_operator(column, 'in')
                else:
                    operator = get_operator(column, op)
            except Exception as exception:
                raise ApiException(str(exception))

            # Create the sqlalchemy query conditions
            if value and column and operator:
                if isinstance(value, dict):
                    condition = getattr(column, operator)(**value)
                else:
                    condition = getattr(column, operator)(value)

                # print("condition: {}".format(str(condition)))
                conditions.append(condition)

        query = query.filter(*conditions)
        # print("filter query: {}".format(str(query)))

    # Handle sort query conditions
    sorting = get_sorting(args)
    if sorting:
        for sort_opt in sorting:
            field = sort_opt['field']
            if not hasattr(model, field):
                raise ApiException("{} has no attribute {}".format(
                    model.__name__, field))

            query = query.order_by(getattr(getattr(model, field),
                                           sort_opt['order'])())

        # print("sort query: {}".format(str(query)))

    # Handle pagination query conditions
    pagination = get_pagination(args)
    if pagination:
        if int(pagination.get('size', 1)) != 0:
            page_size = int(pagination.get('size', 0)) or \
                current_app.config['PAGE_SIZE']
            query = query.limit(page_size)
            if pagination.get('number'):
                query = query.offset((
                    int(pagination['number']) - 1) * page_size)

        # print("pagination query: {}".format(str(query)))

    # print("query: {}".format(str(query)))
    return query


class JSONAPISerializer(object):
    """Custom wrapper to generate `JSON:API <http://jsonapi.org>`_\
    compliant response format
    """

    model = None
    primary_key = 'id'
    fields = []

    def __init__(self, model, fields):
        """Initialize an instance of serializer

        :param object model: sqlalchemy object instance
        :param list fields: list of model fields to be shown in the response
        """

        self.model = model
        self.fields = fields
        if self.model is None:
            raise TypeError("Model cannot be of type 'None'")

        if self.primary_key not in self.fields:
            raise ValueError(
                "Serializer fields must contain primary key '{}'".format(
                    self.primary_key))

    def serialize(self, resources, links, args=None, count=0):
        """Serialization of response data

        :param object resources: response data
        :param object links: URL reference
        :param dict args: request arguments
        :param int count: response data object count
        """

        serialized = {
            'jsonapi': {
                'version': '1.0'
            }
        }

        # Determine multiple resources by checking for SQLAlchemy query count.
        # print("resources: {}".format(str(resources)))
        if hasattr(resources, 'count'):
            serialized['data'] = []
            for resource in resources:
                # print("resource: {}".format(str(resource)))
                if isinstance(resource, dict):
                    top_level = {}
                    top_level['id'] = str(resource.get('id'))
                    top_level['type'] = self.model.__tablename__
                    top_level['attributes'] = resource
                    serialized['data'].append(top_level)
                else:
                    serialized['data'].append(
                        self.handle_resource(resource))

            if len(resources) > 0:
                serialized['meta'] = {
                    'count': len(resources)
                }
        else:
            serialized['data'] = self.handle_resource(resources)

        # Attach the resource links
        # print("serialized data: {}".format(str(serialized['data'])))
        if serialized['data'] and links and links != '':
            serialized['links'] = self.handle_links(links, args, count)

        return serialized

    def handle_resource(self, resource):
        """Render the resource"""

        if not resource:
            return None

        # Must not render a resource that has same named
        # attributes as different model.
        if not isinstance(resource, self.model):
            raise TypeError(
                'Resource type must be the same as the model type.')

        top_level = {}
        try:
            top_level['id'] = str(getattr(resource, self.primary_key))
        except AttributeError:
            raise

        top_level['type'] = resource.__tablename__
        top_level['attributes'] = self.handle_attributes(resource)
        return top_level

    def handle_attributes(self, resource):
        """Render the resource attributes"""

        attributes = {}
        mapped_fields = {x: x for x in self.fields}

        for attribute in self.fields:
            if attribute == self.primary_key:
                continue
            try:
                value = getattr(resource, attribute)
                if isinstance(value, datetime.datetime):
                    attributes[mapped_fields[attribute]] = value.isoformat()
                else:
                    attributes[mapped_fields[attribute]] = value
            except AttributeError:
                raise

        return attributes

    def handle_links(self, url, args, count):
        """Render links used for pagination"""

        links = {}
        links['self'] = url

        # Compute self link
        if not args:
            return links

        qs_args = copy(get_managed_keys(args))
        if qs_args:
            links['self'] += '?' + urlencode(qs_args)

        pagination = get_pagination(args)
        if pagination:
            # print("pagination: {}".format(str(pagination)))
            if pagination.get('size') != '0' and count > 1:
                # Compute last link
                page_size = int(pagination.get('size', 0)) or \
                    current_app.config['PAGE_SIZE']
                last_page = int(ceil(count / page_size))

                # print("page_size: {}".format(str(page_size)))
                # print("last_page: {}".format(str(last_page)))

                if last_page > 1:
                    links['first'] = links['last'] = url
                    qs_args.pop('page[number]', None)

                    # Compute first link
                    if qs_args:
                        links['first'] += '?' + urlencode(qs_args)

                    qs_args.update({'page[number]': last_page})
                    links['last'] += '?' + urlencode(qs_args)

                    # Compute previous and next link
                    current_page = int(pagination.get('number', 0)) or 1
                    if current_page > 1:
                        qs_args.update({'page[number]': current_page - 1})
                        links['prev'] = '?'.join((url, urlencode(qs_args)))
                    if current_page < last_page:
                        qs_args.update({'page[number]': current_page + 1})
                        links['next'] = '?'.join((url, urlencode(qs_args)))

        return links

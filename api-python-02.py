import httplib2
import util
import json

from apiclient.discovery import build
from rest_framework.decorators import api_view
from rest_framework.response import Response

from oauth2client import client

''' Decorator that performs OAuth pre-authorization when access to
    big query API is required
'''
def pre_authorize(func):
    def decorator(*args, **kwargs):
        request = args[0]
        if request.session.get('credentials'):
            credentials = client.OAuth2Credentials.from_json(request.session.get('credentials'))
            http_auth = credentials.authorize(httplib2.Http())
            bigquery_service = build('bigquery', 'v2', http=http_auth)
            kwargs['bigquery'] = bigquery_service
        return func(*args, **kwargs)
    return decorator

''' Returns a list of units for interconnection specified in query parameter
    Endpoint /bigquery/units/?interconnection=<interconnection name>
'''
@api_view(['GET',])
@pre_authorize
def get_units(request, bigquery):
    interconnection = request.query_params['interconnection']
    query_request = bigquery.jobs()
    query_data = {'query':'SELECT UnitID FROM [flx_test.flx_test5] WHERE Interconnect="{}" \
                          GROUP BY UnitID LIMIT 100;'.format(interconnection)}

    query_response = query_request.query(projectId=util.PROJECT_NUMBER, body=query_data).execute()
    rows = query_response['rows']
    result = []
    for row in rows:
        r = row['f']
        result.append({'unitId': r[0]['v']})
    return Response(result)

''' Returns frequency for specific Unit in specific interconnection
    Endpoint /bigquery/units/?interconnection=<interconnection name>&unit_id=<unit id>&limit=<limit>&start=<start sec>
'''
@api_view(['GET',])
@pre_authorize
def get_initial_frequency(request, bigquery):
    interconnection = request.query_params['interconnection']
    uid = 'Unit #'+request.query_params['unit_id']
    limit = request.query_params['limit']
    start = request.query_params['start']
    query_request = bigquery.jobs()
    query_data = {'query':'SELECT UTCtimestamp, Frequency FROM [flx_test.flx_test5] \
                            WHERE Interconnect="{}" AND UnitID="{}" AND UTCtimestamp > {} ORDER BY UTCtimestamp DESC LIMIT {};'.format(interconnection, uid, start,limit)}

    query_response = query_request.query(projectId=util.PROJECT_NUMBER, body=query_data).execute()
    rows = query_response['rows']
    result = []
    for row in rows:
        r = row['f']
        result.append(r[1]['v'])
    return Response(result)

''' Returns available interconnections
    Endpoint /bigquery/interconnections/
'''
@api_view(['GET',])
@pre_authorize
def get_available_interconnections(request, bigquery):

    query_request = bigquery.jobs()
    query_data = {'query':'SELECT Interconnect FROM [flx_test.flx_test5] \
                           GROUP BY Interconnect LIMIT 100;'}

    query_response = query_request.query(projectId=util.PROJECT_NUMBER, body=query_data).execute()
    rows = query_response['rows']
    result = []
    for row in rows:
        r = row['f']
        result.append({'interconnection': r[0]['v'],})
    return Response(result)


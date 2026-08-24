#!/usr/bin/env python3
"""Create the VOC 'SOC Intelligence' dashboards in Kibana.

Creates data views + visualizations + a dashboard for:
  * attack-graph-*         (attack-path / blast-radius graph + Vega force layout)
  * predictions-*          (weekly top-10 exploitation forecast)
  * prediction-validation-* (self-validated precision vs CISA KEV)

Usage (host machine):
    python3 scripts/create_soc_dashboards.py
"""
import json
import os
import subprocess
import sys
import urllib.request

KIBANA = os.getenv('KIBANA_URL', 'http://localhost:5601')

ES_USER = 'elastic'
ES_PASSWORD = os.getenv('ELASTIC_PASSWORD', '')


def _env_password():
    with open('/opt/voc-platform/.env') as f:
        for line in f:
            if line.startswith('ELASTIC_PASSWORD='):
                return line.strip().split('=', 1)[1]
    return ''


def api(path, method='GET', body=None):
    req = urllib.request.Request(f"{KIBANA}{path}", method=method)
    req.add_header('kbn-xsrf', 'true')
    req.add_header('Content-Type', 'application/json')
    import base64
    creds = base64.b64encode(f"{ES_USER}:{ES_PASSWORD}".encode()).decode()
    req.add_header('Authorization', f'Basic {creds}')
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(req, data=data, timeout=30) as resp:
            return resp.status, json.loads(resp.read() or b'{}')
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b'{}')


def create_data_view(dv_id, title, time_field='@timestamp'):
    delete_object('index-pattern', dv_id)
    body = {
        'attributes': {
            'title': title,
            'timeFieldName': time_field,
            'allowNoIndex': True,
        },
        'references': [],
    }
    status, res = api(f'/api/saved_objects/index-pattern/{dv_id}', 'POST', body)
    print(f"  data view {title}: {status}")
    return status in (200, 201)


# ---------------------------------------------------------------------------
# Vega spec: force-directed attack-path graph
# ---------------------------------------------------------------------------
VEGA_GRAPH = {
    '$schema': 'https://vega.github.io/schema/vega/v5.json',
    'width': 900,
    'height': 680,
    'padding': 5,
    'autosize': 'fit',
    'signals': [
        {'name': 'labelThreshold', 'value': 1.0,
         'bind': {'input': 'range', 'min': 0, 'max': 10, 'step': 0.1}}
    ],
    'data': [
        {
            'name': 'raw_nodes',
            'url': {
                'index': 'attack-graph-*',
                'body': {'size': 500,
                         'query': {'bool': {
                             'must': [{'term': {'doc_type': 'node'}}],
                             'filter': [{'range': {'@timestamp': {'%timefilter%': True}}}],
                         }}},
            },
            'format': {'property': 'hits.hits'},
        },
        {
            'name': 'raw_edges',
            'url': {
                'index': 'attack-graph-*',
                'body': {'size': 2000,
                         'query': {'bool': {
                             'must': [{'term': {'doc_type': 'edge'}}],
                             'filter': [{'range': {'@timestamp': {'%timefilter%': True}}}],
                         }}},
            },
            'format': {'property': 'hits.hits'},
        },
        {
            'name': 'nodes',
            'source': 'raw_nodes',
            'transform': [
                {'type': 'formula', 'expr': 'datum._source.ip', 'as': 'id'},
                {'type': 'formula', 'expr': 'datum._source.critical', 'as': 'critical'},
                {'type': 'formula', 'expr': 'datum._source.entry', 'as': 'entry'},
                {'type': 'formula', 'expr': 'datum._source.blast_radius || 0', 'as': 'blast'},
                {'type': 'formula', 'expr': 'datum._source.risk_score || 0', 'as': 'risk'},
                {'type': 'formula', 'expr': 'datum._source.severity', 'as': 'severity'},
            ],
        },
        {
            'name': 'edges',
            'source': 'raw_edges',
            'transform': [
                {'type': 'formula', 'expr': 'datum._source.src', 'as': 'source'},
                {'type': 'formula', 'expr': 'datum._source.tgt', 'as': 'target'},
            ],
        },
        {
            'name': 'nodeLayout',
            'source': 'nodes',
            'transform': [
                {'type': 'force', 'iterations': 300,
                 'link': {'source': 'source', 'target': 'target'},
                 'links': 'edges',
                 'forces': [
                     {'force': 'center', 'x': {'signal': 'width / 2'},
                      'y': {'signal': 'height / 2'}},
                     {'force': 'link', 'distance': 90},
                     {'force': 'collide', 'radius': 18},
                 ]},
            ],
        },
        {
            'name': 'edgeLayout',
            'source': 'edges',
            'transform': [
                {'type': 'lookup', 'from': 'nodeLayout', 'key': 'id',
                 'fields': ['source'], 'as': ['s']},
                {'type': 'lookup', 'from': 'nodeLayout', 'key': 'id',
                 'fields': ['target'], 'as': ['t']},
                {'type': 'formula', 'expr': 'datum.s ? datum.s.x : 0', 'as': 'x1'},
                {'type': 'formula', 'expr': 'datum.s ? datum.s.y : 0', 'as': 'y1'},
                {'type': 'formula', 'expr': 'datum.t ? datum.t.x : 0', 'as': 'x2'},
                {'type': 'formula', 'expr': 'datum.t ? datum.t.y : 0', 'as': 'y2'},
            ],
        },
    ],
    'scales': [
        {'name': 'colorScale', 'type': 'ordinal',
         'domain': ['critical', 'entry', 'normal'],
         'range': ['#e74c3c', '#f39c12', '#3498db']},
        {'name': 'sizeScale', 'type': 'linear',
         'domain': {'data': 'nodeLayout', 'field': 'blast'}, 'range': [12, 60]},
    ],
    'marks': [
        {
            'type': 'line',
            'from': {'data': 'edgeLayout'},
            'encode': {
                'update': {
                    'x1': {'field': 'x1'}, 'y1': {'field': 'y1'},
                    'x2': {'field': 'x2'}, 'y2': {'field': 'y2'},
                    'stroke': {'value': '#5a5a5a'},
                    'strokeWidth': {'value': 1},
                    'strokeOpacity': {'value': 0.55},
                },
            },
        },
        {
            'type': 'symbol',
            'from': {'data': 'nodeLayout'},
            'encode': {
                'enter': {
                    'tooltip': {'signal':
                        "datum.id + '\\nrisk=' + datum.risk + ' blast=' + datum.blast + ' ' + datum.severity"},
                },
                'update': {
                    'x': {'field': 'x'}, 'y': {'field': 'y'},
                    'size': {'scale': 'sizeScale', 'field': 'blast'},
                    'fill': {'scale': 'colorScale',
                             'signal': "datum.critical ? 'critical' : (datum.entry ? 'entry' : 'normal')"},
                    'stroke': {'value': 'white'},
                    'strokeWidth': {'value': 1.5},
                },
            },
        },
        {
            'type': 'text',
            'from': {'data': 'nodeLayout'},
            'encode': {
                'update': {
                    'x': {'field': 'x'}, 'y': {'field': 'y', 'offset': -12},
                    'text': {'field': 'id'}, 'fill': {'value': '#dddddd'},
                    'fontSize': {'value': 10},
                    'opacity': {'signal': 'datum.blast > labelThreshold ? 1 : 0'},
                },
            },
        },
    ],
}


def vis_object(vid, title, vis_type, vis_state, dv_id):
    return {
        'attributes': {
            'title': title,
            'description': '',
            'visState': json.dumps(vis_state),
            'kibanaSavedObjectMeta': {
                'searchSourceJSON': json.dumps({
                    'query': {'query': '', 'language': 'kuery'},
                    'filter': [],
                    'index': dv_id,
                }),
            },
        },
        'references': [
            {'name': 'kibanaSavedObjectMeta.searchSourceJSON.index',
             'type': 'index-pattern', 'id': dv_id},
        ],
    }


def bar_state(title, agg_field, metric_field, size=10, label_agg='cve'):
    return {
        'title': title,
        'type': 'horizontal_bar',
        'params': {
            'type': 'histogram',
            'grid': {'valueLines': 'shown'},
            'categoryAxes': [{
                'id': 'CategoryAxis-1', 'type': 'category', 'position': 'bottom',
                'show': True, 'style': {}, 'scale': {'type': 'linear'},
                'labels': {'show': True, 'truncate': 100}, 'title': {},
            }],
            'valueAxes': [{
                'id': 'ValueAxis-1', 'name': 'LeftAxis-1', 'type': 'value',
                'position': 'left', 'show': True, 'style': {},
                'scale': {'type': 'linear', 'mode': 'normal'}, 'labels': {'show': True},
                'title': {'text': ''},
            }],
            'seriesParams': [{
                'show': 'true', 'type': 'histogram', 'mode': 'stacked',
                'data': {'label': agg_field, 'id': '1'},
                'valueAxis': 'ValueAxis-1', 'drawLinesBetweenPoints': True,
                'showCircles': True,
            }],
            'addTooltip': True, 'addLegend': True,
            'legendPosition': 'right', 'timeseries': {}, 'orderBucketsBySum': False,
        },
        'aggs': [
            {'id': '1', 'enabled': True, 'type': 'terms', 'schema': 'segment',
             'params': {'field': agg_field, 'size': size,
                        'order': {'2': 'desc'}, 'orderBy': '2',
                        'otherBucket': False, 'missingBucket': False}},
            {'id': '2', 'enabled': True, 'type': 'max', 'schema': 'metric',
             'params': {'field': metric_field}},
        ],
    }


def table_state(title, columns):
    return {
        'title': title,
        'type': 'table',
        'params': {
            'perPage': 20, 'showPartialRows': False, 'showMetricsAtAllLevels': False,
            'showTotal': False, 'totalFunc': 'sum',
            'sort': {'columnIndex': None, 'direction': None},
            'showToolbar': True,
        },
        'aggs': [
            {'id': '1', 'enabled': True, 'type': 'terms', 'schema': 'bucket',
             'params': {'field': c['field'], 'size': c.get('size', 100),
                        'order': {'_key': 'asc'}, 'orderBy': '_key'}}
            for c in columns
        ],
    }


def delete_object(obj_type, obj_id):
    status, _ = api(f'/api/saved_objects/{obj_type}/{obj_id}', 'DELETE')
    if status == 404:
        return
    if status not in (200, 404):
        print(f"  ! delete {obj_type}/{obj_id}: {status}")


def create_visualization(vid, title, state, dv_id):
    delete_object('visualization', vid)
    body = vis_object(vid, title, state['type'], state, dv_id)
    status, res = api(f'/api/saved_objects/visualization/{vid}', 'POST', body)
    print(f"  visualization {title}: {status}")
    return status in (200, 201)


def create_dashboard(did, title, panels):
    delete_object('dashboard', did)
    panels_json = []
    references = []
    for i, (pid, title_, w, h, x, y) in enumerate(panels, start=1):
        panel_index = str(i)
        panels_json.append({
            'version': '8.11.0',
            'gridData': {'x': x, 'y': y, 'w': w, 'h': h, 'i': panel_index},
            'panelIndex': panel_index,
            'type': 'visualization',
            'id': pid,
            'embeddableConfig': {'title': title_},
        })
        references.append({'name': f'{panel_index}:panel_{panel_index}',
                           'type': 'visualization', 'id': pid})
    body = {
        'attributes': {
            'title': title,
            'hits': 0,
            'description': 'VOC SOC Intelligence',
            'panelsJSON': json.dumps(panels_json),
            'optionsJSON': json.dumps({'useMargins': True, 'syncColors': False,
                                       'hidePanelTitles': False}),
            'timeRestore': False,
            'timeFrom': 'now-30d',
            'timeTo': 'now',
        },
        'references': references,
    }
    status, res = api(f'/api/saved_objects/dashboard/{did}', 'POST', body)
    print(f"  dashboard {title}: {status}")


def main():
    global ES_PASSWORD
    ES_PASSWORD = _env_password()
    if not ES_PASSWORD:
        print('ERROR: could not read ELASTIC_PASSWORD from .env', file=sys.stderr)
        sys.exit(1)
    print('Creating SOC Intelligence dashboards...')

    print(' Data views:')
    for dv in ('attack-graph-*', 'predictions-*', 'prediction-validation-*'):
        create_data_view(dv, dv)

    print(' Visualizations:')
    create_visualization(
        'voc-attack-graph',
        'Attack Path / Blast Radius (force-directed)',
        {'title': 'Attack Path Graph', 'type': 'vega',
         'params': {'spec': VEGA_GRAPH, 'mode': 'vega'}},
        'attack-graph-*',
    )
    create_visualization(
        'voc-blast-radius',
        'Blast Radius - Top Assets',
        bar_state('Blast Radius - Top Assets', 'ip.keyword', 'blast_radius', size=15),
        'attack-graph-*',
    )
    create_visualization(
        'voc-prediction-top10',
        'Top-10 Predicted Exploits (next 7 days)',
        bar_state('Top-10 Predicted Exploits', 'top10.cve.keyword', 'top10.pred_score', size=10),
        'predictions-*',
    )
    create_visualization(
        'voc-validation-precision',
        'Prediction Precision @10 over time',
        bar_state('Prediction Precision @10', 'prediction_date', 'precision_at_10', size=50),
        'prediction-validation-*',
    )
    create_visualization(
        'voc-validation-table',
        'Prediction Validation Details',
        {
            'title': 'Prediction Validation Details',
            'type': 'table',
            'params': {
                'perPage': 20, 'showPartialRows': False, 'showMetricsAtAllLevels': False,
                'showTotal': False, 'totalFunc': 'sum',
                'sort': {'columnIndex': 0, 'direction': 'desc'},
                'showToolbar': True,
            },
            'aggs': [
                {'id': '1', 'enabled': True, 'type': 'terms', 'schema': 'bucket',
                 'params': {'field': 'prediction_date', 'size': 100,
                            'order': {'_key': 'desc'}, 'orderBy': '_key'}},
                {'id': '2', 'enabled': True, 'type': 'avg', 'schema': 'metric',
                 'params': {'field': 'precision_at_10'}},
                {'id': '3', 'enabled': True, 'type': 'avg', 'schema': 'metric',
                 'params': {'field': 'precision_new_at_10'}},
            ],
        },
        'prediction-validation-*',
    )

    print(' Dashboard:')
    create_dashboard('voc-soc-intelligence', 'VOC - SOC Intelligence', [
        ('voc-attack-graph', 'Attack Path / Blast Radius', 12, 7, 0, 0),
        ('voc-blast-radius', 'Blast Radius - Top Assets', 4, 7, 0, 7),
        ('voc-prediction-top10', 'Top-10 Predicted Exploits', 4, 7, 4, 7),
        ('voc-validation-precision', 'Prediction Precision @10', 4, 7, 8, 7),
        ('voc-validation-table', 'Prediction Validation Details', 12, 4, 0, 14),
    ])


if __name__ == '__main__':
    main()
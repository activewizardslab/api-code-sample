# -*- coding: utf-8 -*-

from flask import (
    Flask, request, redirect, url_for, render_template,jsonify)
from flask.ext.login import (
    LoginManager, login_required, login_user, UserMixin, logout_user, current_user)
from flask.ext.bcrypt import Bcrypt
import json
import re
import utils.MongoApi as MgApi
from utils.settings import db_session
from utils.ORMClasses import Site, User
import ast

# configuration
SECRET_KEY = 'development key'

app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('FLASKR_SETTINGS', silent=True)

login_manager = LoginManager(app)
login_manager.init_app(app)

bcrypt = Bcrypt(app)

# for debug on server
app.config['DEBUG'] = True

from werkzeug.debug import DebuggedApplication
app.wsgi_app = DebuggedApplication( app.wsgi_app, True )

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.close()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/auth')
def auth():
    user = str(request.args.get('user'))
    password = str(request.args.get('pass'))
    pass_hash = bcrypt.generate_password_hash(password)
    user = User(user, pass_hash)
    db_session.add(user)
    db_session.commit()
    db_session.close()
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        try:
            user = User.query.filter_by(username=request.form['username'])[0]
            if bcrypt.check_password_hash(user.password, request.form['password']):
                login_user(user)
                return redirect(url_for('index'))
            else:
                error = "Username or password is incorrect"
        except IndexError:
            error = "Username or password is incorrect"
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/api/get_report/')
@login_required
def get_report():
    start_date = request.args.get('begin') and str(request.args.get('begin')) or None
    end_date = request.args.get('end') and str(request.args.get('end')) or None

    data = {'traffic_per_countries': MgApi.get_top_countries_traffic(start_date, end_date),
            'traffic_per_server': MgApi.get_top_server_traffic(start_date, end_date),
            'top_keywords': MgApi.get_top_keywords(start_date, end_date),
            'top_sites': MgApi.get_top_traffic(start_date, end_date),
            'worst_sites': MgApi.get_bottom_traffic(start_date, end_date),
            'visitors_info': MgApi.get_visitors_info(start_date, end_date),
            'visitors_traffic': MgApi.get_visitors_traffic(date_begin=start_date, date_end=end_date),
            'trending_sites': MgApi.get_top_trending_sites(start_date, end_date),
            'start_date': start_date,
	    'end_date': end_date    
    }
    return jsonify(**{'data': data})

@app.route('/api/get_report/site/')
@login_required
def get_report_site():
    url = request.args.get('site')
    start_date = request.args.get('begin') and str(request.args.get('begin')) or None
    end_date = request.args.get('end') and str(request.args.get('end')) or None

    site_data = {
            'site_url':url,
            'site_info': MgApi.get_data_from_mysql(url),
            'visitors_traffic_site': MgApi.get_visitors_traffic_for_site(url,date_begin=start_date, date_end=end_date),
            'traffic_last_week': MgApi.traffic_for_last_7_days(url),
            'site_rank': MgApi.ranks(url),
            'traffic_per_countries_site': MgApi.get_country_rank_for_site(url, start_date, end_date),
            'site_specific_info':MgApi.get_site_specific_info(url, date_begin=start_date, date_end=end_date),
            'top_keywords_site':MgApi.get_top_keywords_for_site(url, start_date, end_date)}
    return jsonify(**{'data': site_data})

@app.route('/api/get_report/analytics/')
@login_required
def get_report_analytics():
    url = request.args.get('site')
    start_date = request.args.get('begin') and str(request.args.get('begin')) or None
    end_date = request.args.get('end') and str(request.args.get('end')) or None

    analytics_data = {
            'site_info': MgApi.get_data_from_mysql(url),
            'visitors_traffic_site': MgApi.get_visitors_traffic_for_site(url,start_date, end_date)
            }
    return jsonify(**{'data': analytics_data})

@app.route('/api/get_report/manage/', methods=['GET', 'POST'])
@login_required
def get_report_manage():
    '''
        get_sites kwargs types:
            page - int or unicode
            url - str
            user_id - list
            lang - list
            application_type - list
            server - list
            creation_date_min - str
            creation_date_max - str
            traffic_min - int or unicode
            traffic_max - int or unicode
            sort_by - str
            asc - int or unicode
    '''
    #TODO: the default behavior when there is no filtering by 'user_id'
    filters = MgApi.manage_filters()
    selected_filters = request.args.to_dict()
    p = re.compile(r'\[(.)*\]')
    for k, v in selected_filters.iteritems():
        if p.match(str(v)):
            selected_filters[k]=ast.literal_eval(v)
    print selected_filters

    if selected_filters:
        site_info = MgApi.get_sites(**selected_filters)
    else:
        site_info = MgApi.get_sites(user_id = int(filters[0]['user_id']))

    manage_data = {
            'site_info': site_info,
            'filters': filters
            }
    return jsonify(**{'data': manage_data})

@app.route('/api/get_report/manage/filters', methods=['GET', 'POST'])
@login_required
def get_filters():
    data = {
            'filters': MgApi.manage_filters()
            }
    return jsonify(**{'data': data})


@app.route('/api/get_report/online_users')
def get_online_users():
    args = request.args.to_dict()
    if 'url' in args:

        if len(args['url'].split(','))<=1:
            if 'ticks' in args:
                data = MgApi.total_online(url=args['url'],ticks=int(args['ticks']))
            else:
                data = MgApi.total_online(url=args['url'],ticks=2)
        else:
            if 'ticks' in args:
                data = MgApi.total_online(url=args['url'],ticks=int(args['ticks']),multiple=True)
            else:
                data = MgApi.total_online(url=args['url'],ticks=2,multiple=True)

    else:
        if 'ticks' in args:
            data = MgApi.total_online(ticks=int(args['ticks']))

        else:
            data = MgApi.total_online(ticks=2)

    if 'ticks' not in args:
        
        if data[0]['total_online']!=0:
            diff = float(data[1]['total_online'])/data[0]['total_online']
        else:
            diff = float(data[1]['total_online'])/1

        data = data[1]
        data['diff'] = diff
        return jsonify(data)
    else:
        return jsonify({'data':data})

@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/manage')
@login_required
def manage():
    return render_template('manage.html')


@app.route('/logs')
@login_required
def logs():
    return render_template('logs.html')


@app.route('/seo')
@login_required
def seo():
    url = request.args.get('site')
    return render_template('seo.html', url=url)


@app.route('/site')
@login_required
def site():
    url = request.args.get('site')
    return render_template('site.html', url=url)

	
@app.route('/analytics')
@login_required
def analytics():
    url = request.args.get('site')
    return render_template('analytics.html', url=url)


@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for('login'))


@app.errorhandler(404)
@login_required
def page_not_found(e):
    return render_template('404.html'), 404


@app.route('/api/get_ahref_info/')
@login_required
def get_ahref_info():
    url = request.args.get('site')
    ahref_data = {
            "ahrefs_rank": MgApi.get_ahref_rating(url),
            "reffering_domains": MgApi.get_reffering_domains(url),
            "total_backlinks": MgApi.get_total_backlinks(url),
            "total_backlinks_uniq_domains": MgApi.get_total_backlinks_uniq_domains(url),
            "total_backlinks_by_dom_uniq_ip": MgApi.get_total_backlinks_by_dom_uniq_ip(url),
            "total_backlinks_by_subdom_uniiq_ip": MgApi.get_total_backlinks_by_subdom_uniq_ip(url),
            "total_backlinks_by_dom_ip": MgApi.get_total_backlinks_by_dom_ip(url),
            "count_by_type_dom": MgApi.get_count_type_domains(url),
            #"alexa_rank": MgApi.get_alexa_rank(url),
            }
    return jsonify(**{'data': ahref_data})


if __name__ == '__main__':
    app.run(debug=True)

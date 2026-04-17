import logging
import werkzeug
from werkzeug.urls import url_encode

from odoo import http, tools, _
from odoo.addons.auth_signup.models.res_users import SignupError
from odoo.addons.web.controllers.home import ensure_db, Home, SIGN_UP_REQUEST_PARAMS, LOGIN_SUCCESSFUL_PARAMS
from odoo.addons.web.models.res_users import SKIP_CAPTCHA_LOGIN
from odoo.addons.base_setup.controllers.main import BaseSetup
from odoo.exceptions import UserError
from odoo.tools.translate import LazyTranslate
from odoo.http import request
from markupsafe import Markup
import json
from odoo.tools import consteq
from odoo.tools import misc
import hashlib
import hmac
import time

_lt = LazyTranslate(__name__)
_logger = logging.getLogger(__name__)

LOGIN_SUCCESSFUL_PARAMS.add('account_created')

class CustomMobileAuthHandler(Home):

    @http.route('/web/mobile-login', type='http', auth='public', website=True, sitemap=False, captcha='login', list_as_website_content=_lt("Mobile Login"))
    def web_mobile_login(self, *args, **kw):
        return request.render('custom_website.mobile_login_template')


    @http.route('/web/mobile/verify', type='http', auth='public', website=True, sitemap=False, captcha='login', list_as_website_content=_lt("Mobile Verification"))
    def web_mobile_verification(self, *args, **kw):
        country_obj = request.env['res.country'].sudo().browse(int(kw['country_id']))
        if not country_obj:
            raise UserError(_(f"Invalid Country"))

        kw['mobile'] = f"+{country_obj.phone_code}{kw['mobile']}"
        mobile = kw.get('mobile')

        partner_obj = request.env['res.partner'].sudo().search(
            [
                ('phone','=',mobile)
            ],
            limit=1
        )

        if not partner_obj:
            raise UserError(_("User does not exists, please Sign up."))

        user = request.env['res.users'].sudo().search(
            [
                ('partner_id','=',partner_obj.id)
            ],
            limit=1
        )


        if not user:
            raise UserError(_("User does not exists, please Sign up."))


        otp = self.send_otp_on_mail_phone(kw.get("mobile"), user.login)

        request.session['signup_otp_data'] = {
                'login': user.login,
                'id': user.id,
                'mobile': mobile,
                'otp': otp,
                'type': 'login'

            }
        return request.render('custom_website.otp_verify_template', kw)




    @http.route('/web/mobile/forgot-password', type='http', auth='public', website=True, sitemap=False, captcha='login', list_as_website_content=_lt("Mobile Login"))
    def web_mobile_forgot_password_render(self, *args, **kw):
        return request.render('custom_website.mobile_forgot_password_template')


    @http.route('/web/mobile/confirm', type='http', auth='public', website=True, sitemap=False, captcha='login', list_as_website_content=_lt("Mobile Login"))
    def web_mobile_confirm(self, *args, **kw):
        partner = request.env['res.partner'].sudo().search(
            [('phone', '=', kw['mobile'])],
            limit=1
        )

        if not partner:
            raise UserError(_("Customer not exists with this mobile."))

        user = request.env['res.users'].sudo().search(
            [('partner_id', '=', partner.id)],
            limit=1
        )



        otp = self.send_otp_on_mail_phone(partner.phone, user.login)
        request.session['signup_otp_data'] = {
            'login': user.login,
            'mobile': partner.phone,
            'otp': otp,
            'type': 'login'
        }
        return request.render('custom_website.otp_verify_template', kw)



        @http.route('/web/mobile/reset-password', type='http', auth='public', website=True, sitemap=False, captcha='login', list_as_website_content=_lt("Mobile Login"))
        def web_mobile_reset_password(self, *args, **kw):
            signup_data = request.session.get('signup_otp_data')
            password = kw.get("password")
            confirm_password = kw.get("confirm_password")

            if password != confirm_password:
                raise UserError(_("Password and confirm password should be same."))

            user = request.env['res.users'].sudo().search(
                [
                    ('login','=',signup_data['login'])
                ],
                limit=1
            )


        if not user:
            raise UserError(_("User does not exists!"))

        user.sudo().write({'password': password})

        credential = {
            'login': user.login,
            'password': password,
            'type': 'password',
        }

        request.session.pop('signup_otp_data', None)

        request.session.authenticate(
            request.env,
            credential
        )

        return request.redirect('/web')



    @http.route('/web/mobile/check_user', type='json', auth='public', website=True)
        def check_mobile_user(self, country_id, mobile):
            # 1. कंट्री कोड निकालें और नंबर फॉर्मेट करें
            country = request.env['res.country'].sudo().browse(int(country_id))
            if not country:
                return {'exists': False, 'message': "Invalid country selection."}

            full_mobile = f"+{country.phone_code}{mobile}"

            # 2. पार्टनर और यूजर सर्च करें
            partner = request.env['res.partner'].sudo().search([
                ('phone', '=', full_mobile)
            ], limit=1)

            user_exists = False
            if partner:
                user = request.env['res.users'].sudo().search([
                    ('partner_id', '=', partner.id)
                ], limit=1)
                if user:
                    user_exists = True

            # 3. रिस्पॉन्स भेजें
            if user_exists:
                return {'exists': True}
            else:
                error_message = Markup(_("Is number se koi account nahi mila. Kripya <a href='/web/signup'>Sign Up</a> karein."))
                return {
                    'exists': False,
                    'message': error_message
                }

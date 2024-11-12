import os
import json
import base64
import re
from django.shortcuts import redirect
from django.http import JsonResponse
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from dotenv import load_dotenv

load_dotenv()

CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send']
REDIRECT_URI = 'http://127.0.0.1:8000/api/google_auth/callback/'


class GoogleExtractor:

    def authenticate_gmail(self, authorization_response):
        flow = Flow.from_client_secrets_file(
            'credentials.json',
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI
        )
        flow.fetch_token(authorization_response=authorization_response)

        creds = flow.credentials

        with open('token.json', 'w') as token:
            token.write(creds.to_json())

        return creds

    def file_name(self, filename):
        return re.sub(r'[<>:"/\\|?*]', '_', filename)

    def get_all_emails(self, service, folder_name, is_sent=False):
        messages = []
        page_token = None

        while True:
            results = service.users().messages().list(
                userId='me',
                labelIds=['SENT'] if is_sent else ['INBOX'],
                pageToken=page_token
            ).execute()

            messages.extend(results.get('messages', []))
            page_token = results.get('nextPageToken')

            if not page_token:
                break

        if not messages:
            return []

        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
            headers = msg['payload']['headers']
            body = self.get_body(msg)

            sender_or_recipient = None
            for header in headers:
                if header['name'] == 'From' and not is_sent:
                    sender_or_recipient = header['value']
                elif header['name'] == 'To' and is_sent:
                    sender_or_recipient = header['value']

            if sender_or_recipient:
                sanitized_sender = self.sanitize_filename(sender_or_recipient)
                folder_path = os.path.join('emails', folder_name, sanitized_sender)
                if not os.path.exists(folder_path):
                    os.makedirs(folder_path)

                file_path = os.path.join(folder_path, f'{message["id"]}.txt')
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(f"From/To: {sender_or_recipient}\n")
                    file.write(f"Message Body: {body}\n")

        return True

    def get_body(self, msg):
        body = ''
        if 'parts' in msg['payload']:
            for part in msg['payload']['parts']:
                if part['mimeType'] == 'text/plain':
                    body = part['body'].get('data', '')
                    break
        elif 'body' in msg['payload']:
            body = msg['payload']['body'].get('data', '')

        if body:
            body = base64.urlsafe_b64decode(body).decode('utf-8')

        return body


def google_auth(request):
    extractor = GoogleExtractor()
    flow = Flow.from_client_secrets_file(
        'credentials.json',
        scopes=['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send'],
        redirect_uri=REDIRECT_URI
    )

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )

    request.session['state'] = state

    return redirect(authorization_url)


def google_auth_callback(request):
    extractor = GoogleExtractor()
    state = request.session.get('state')

    flow = Flow.from_client_secrets_file(
        'credentials.json',
        scopes=['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send'],
        state=state,
        redirect_uri=REDIRECT_URI
    )

    flow.fetch_token(authorization_response=request.build_absolute_uri())

    creds = flow.credentials

    service = build('gmail', 'v1', credentials=creds)

    extractor.get_all_emails(service, 'incoming_emails')

    extractor.get_all_emails(service, 'sent_emails', is_sent=True)

    return JsonResponse({"message": "Emails retrieved and saved successfully."})

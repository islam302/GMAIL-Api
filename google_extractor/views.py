from django.shortcuts import redirect
from django.http import JsonResponse
import os
import google.auth
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from dotenv import load_dotenv


class GoogleExtractor:

    def __init__(self):
        load_dotenv()
        openai.api_key = os.getenv('GOOGLE_CLOUD_CONSOLE')
        self.SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


    def authenticate_gmail(self):
        creds = None
        # Load credentials from token if it exists
        if os.path.exists('token.json'):
            creds = Credentials.from_authorized_user_file('token.json', self.SCOPES)

        # If there are no valid credentials, let the user log in
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file('credentials.json', self.SCOPES)
                creds = flow.run_local_server(port=0)

            # Save the credentials for the next run
            with open('token.json', 'w') as token:
                token.write(creds.to_json())

        return creds

    def get_emails(self, service):
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=10).execute()
        messages = results.get('messages', [])

        senders = []
        recipients = []

        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
            headers = msg['payload']['headers']
            for header in headers:
                if header['name'] == 'From':
                    senders.append(header['value'])
                elif header['name'] == 'To':
                    recipients.append(header['value'])

        return senders, recipients


def extract_emails(request):
    extractor = GoogleExtractor()
    creds = extractor.authenticate_gmail()
    service = build('gmail', 'v1', credentials=creds)

    senders, recipients = extractor.get_emails(service)

    return JsonResponse({"message": "Emails retrieved successfully.", "senders": senders, "recipients": recipients})

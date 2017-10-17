import pytest
from django.core import mail as djmail
from django.urls import reverse

from pretalx.submission.models import SubmissionStates


@pytest.mark.django_db
def test_can_see_submission_list(speaker_client, submission):
    response = speaker_client.get(
        submission.event.urls.user_submissions,
        follow=True,
    )
    assert response.status_code == 200
    assert submission.title in response.content.decode()


@pytest.mark.django_db
def test_can_see_submission(speaker_client, submission):
    response = speaker_client.get(
        submission.urls.user_base,
        follow=True,
    )
    assert response.status_code == 200
    assert submission.title in response.content.decode()


@pytest.mark.django_db
def test_cannot_see_other_submission(speaker_client, other_submission):
    response = speaker_client.get(
        other_submission.urls.user_base,
        follow=True,
    )
    assert response.status_code == 404


@pytest.mark.django_db
def test_can_confirm_submission(speaker_client, accepted_submission):
    response = speaker_client.get(
        accepted_submission.urls.confirm,
        follow=True,
    )
    accepted_submission.refresh_from_db()
    assert response.status_code == 200
    assert accepted_submission.state == SubmissionStates.CONFIRMED


@pytest.mark.django_db
def test_can_reconfirm_submission(speaker_client, accepted_submission):
    accepted_submission.state = SubmissionStates.CONFIRMED
    accepted_submission.save()
    response = speaker_client.get(
        accepted_submission.urls.confirm,
        follow=True,
    )
    accepted_submission.refresh_from_db()
    assert response.status_code == 200
    assert accepted_submission.state == SubmissionStates.CONFIRMED


@pytest.mark.django_db
def test_cannot_confirm_rejected_submission(speaker_client, rejected_submission):
    rejected_submission.state = SubmissionStates.REJECTED
    rejected_submission.save()
    response = speaker_client.get(
        rejected_submission.urls.confirm,
        follow=True,
    )
    rejected_submission.refresh_from_db()
    assert response.status_code == 200
    assert rejected_submission.state == SubmissionStates.REJECTED


@pytest.mark.django_db
def test_can_withdraw_submission(speaker_client, submission):
    response = speaker_client.get(
        submission.urls.withdraw,
        follow=True,
    )
    submission.refresh_from_db()
    assert response.status_code == 200
    assert submission.state == SubmissionStates.WITHDRAWN


@pytest.mark.django_db
def test_cannot_withdraw_accepted_submission(speaker_client, accepted_submission):
    response = speaker_client.get(
        accepted_submission.urls.withdraw,
        follow=True,
    )
    accepted_submission.refresh_from_db()
    assert response.status_code == 200
    assert accepted_submission.state == SubmissionStates.ACCEPTED


@pytest.mark.django_db
def test_can_edit_submission(speaker_client, submission):
    data = {
        'title': 'Ein ganz neuer Titel',
        'submission_type': submission.submission_type.pk,
        'content_locale': submission.content_locale,
        'description': submission.description,
        'abstract': submission.abstract,
        'notes': submission.notes,
    }
    response = speaker_client.post(
        submission.urls.user_base + '/',
        follow=True, data=data,
    )
    assert response.status_code == 200
    submission.refresh_from_db()
    assert submission.title == 'Ein ganz neuer Titel', response.content.decode()


@pytest.mark.django_db
def test_cannot_edit_rejected_submission(speaker_client, rejected_submission):
    title = rejected_submission.title
    data = {
        'title': 'Ein ganz neuer Titel',
        'submission_type': rejected_submission.submission_type.pk,
        'content_locale': rejected_submission.content_locale,
        'description': rejected_submission.description,
        'abstract': rejected_submission.abstract,
        'notes': rejected_submission.notes,
    }
    response = speaker_client.post(
        rejected_submission.urls.user_base,
        follow=True, data=data,
    )
    assert response.status_code == 200
    rejected_submission.refresh_from_db()
    assert rejected_submission.title == title


@pytest.mark.django_db
def test_can_edit_profile(speaker, event, speaker_client):
    response = speaker_client.post(
        event.urls.user,
        data={'name': 'Lady Imperator', 'biography': 'Ruling since forever.', 'form': 'profile'},
        follow=True,
    )
    assert response.status_code == 200
    speaker.refresh_from_db()
    assert speaker.profiles.get(event=event).biography == 'Ruling since forever.'
    assert speaker.name == 'Lady Imperator'


@pytest.mark.django_db
def test_can_edit_and_update_speaker_answers(
        speaker, event, speaker_question, speaker_boolean_question, speaker_client,
        speaker_text_question,
):
    answer = speaker.answers.filter(question_id=speaker_question.pk).first()
    assert not answer
    response = speaker_client.post(
        event.urls.user,
        data={
            f'question_{speaker_question.id}': 'black as the night',
            f'question_{speaker_boolean_question.id}': 'True',
            f'question_{speaker_text_question.id}': 'Green is totally the best color.',
            'form': 'questions'
        },
        follow=True,
    )
    assert response.status_code == 200
    answer = speaker.answers.get(question_id=speaker_question.pk)
    assert answer.answer == 'black as the night'
    assert speaker.answers.get(question_id=speaker_boolean_question.pk).answer == 'True'
    assert speaker.answers.get(question_id=speaker_text_question.pk).answer == 'Green is totally the best color.'
    response = speaker_client.post(
        event.urls.user,
        data={f'question_{speaker_question.id}': 'green as the sky', 'form': 'questions'},
        follow=True,
    )
    assert response.status_code == 200
    answer.refresh_from_db()
    assert answer.answer == 'green as the sky'


@pytest.mark.django_db
def test_can_delete_profile(speaker, event, speaker_client):
    assert speaker.profiles.get(event=event).biography != ''
    response = speaker_client.post(
        event.urls.user_delete,
        data={'really': True},
        follow=True,
    )
    assert response.status_code == 200
    speaker.refresh_from_db()
    assert speaker.profiles.get(event=event).biography == ''
    assert speaker.name == 'Deleted User'
    assert speaker.nick.startswith('deleted_user')
    assert speaker.email.startswith('deleted_user')
    assert speaker.email.endswith('@localhost')


@pytest.mark.django_db
def test_can_change_locale(multilingual_event, client):
    first_response = client.get(multilingual_event.urls.base, follow=True)
    assert 'submission' in first_response.content.decode()
    assert 'Einreichung' not in first_response.content.decode()
    second_response = client.get(
        reverse('cfp:locale.set', kwargs={'event': multilingual_event.slug}) + f'?locale=de&next=/{multilingual_event.slug}/',
        follow=True,
    )
    assert 'Einreichung' in second_response.content.decode()


@pytest.mark.django_db
def test_persists_changed_locale(multilingual_event, orga_user, orga_client):
    assert orga_user.locale == 'en'
    response = orga_client.get(
        reverse('cfp:locale.set', kwargs={'event': multilingual_event.slug}) + f'?locale=de&next=/{multilingual_event.slug}/',
        follow=True,
    )
    orga_user.refresh_from_db()
    assert response.status_code == 200
    assert orga_user.locale == 'de'


@pytest.mark.django_db
def test_can_invite_speaker(speaker_client, submission):
    djmail.outbox = []
    response = speaker_client.get(submission.urls.invite, follow=True)
    assert response.status_code == 200
    data = {
        'speaker': 'other@speaker.org',
        'subject': 'Please join!',
        'text': 'C\'mon, it will be fun!',
    }
    response = speaker_client.post(
        submission.urls.invite,
        follow=True, data=data,
    )
    assert response.status_code == 200
    assert len(djmail.outbox) == 1
    assert djmail.outbox[0].to == ['other@speaker.org']


@pytest.mark.django_db
def test_can_accept_invitation(orga_client, submission):
    assert submission.speakers.count() == 1
    response = orga_client.post(submission.urls.accept_invitation, follow=True)
    submission.refresh_from_db()
    assert response.status_code == 200
    assert submission.speakers.count() == 2

# Generated by Django 5.1.3 on 2024-12-06 20:13

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='UrlMetrics',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('website', models.CharField(default='', max_length=200)),
                ('qty_dot_url', models.IntegerField()),
                ('qty_hyphen_url', models.IntegerField()),
                ('qty_underline_url', models.IntegerField()),
                ('qty_slash_url', models.IntegerField()),
                ('qty_questionmark_url', models.IntegerField()),
                ('qty_equal_url', models.IntegerField()),
                ('qty_at_url', models.IntegerField()),
                ('qty_and_url', models.IntegerField()),
                ('qty_exclamation_url', models.IntegerField()),
                ('qty_space_url', models.IntegerField()),
                ('qty_tilde_url', models.IntegerField()),
                ('qty_comma_url', models.IntegerField()),
                ('qty_plus_url', models.IntegerField()),
                ('qty_asterisk_url', models.IntegerField()),
                ('qty_hashtag_url', models.IntegerField()),
                ('qty_dollar_url', models.IntegerField()),
                ('qty_percent_url', models.IntegerField()),
                ('qty_tld_url', models.IntegerField()),
                ('length_url', models.IntegerField()),
                ('qty_dot_domain', models.IntegerField()),
                ('qty_hyphen_domain', models.IntegerField()),
                ('qty_underline_domain', models.IntegerField()),
                ('qty_slash_domain', models.IntegerField()),
                ('qty_questionmark_domain', models.IntegerField()),
                ('qty_equal_domain', models.IntegerField()),
                ('qty_at_domain', models.IntegerField()),
                ('qty_and_domain', models.IntegerField()),
                ('qty_exclamation_domain', models.IntegerField()),
                ('qty_space_domain', models.IntegerField()),
                ('qty_tilde_domain', models.IntegerField()),
                ('qty_comma_domain', models.IntegerField()),
                ('qty_plus_domain', models.IntegerField()),
                ('qty_asterisk_domain', models.IntegerField()),
                ('qty_hashtag_domain', models.IntegerField()),
                ('qty_dollar_domain', models.IntegerField()),
                ('qty_percent_domain', models.IntegerField()),
                ('qty_vowels_domain', models.IntegerField()),
                ('domain_length', models.IntegerField()),
                ('domain_in_ip', models.IntegerField()),
                ('server_client_domain', models.IntegerField()),
                ('qty_dot_directory', models.IntegerField()),
                ('qty_hyphen_directory', models.IntegerField()),
                ('qty_underline_directory', models.IntegerField()),
                ('qty_slash_directory', models.IntegerField()),
                ('qty_questionmark_directory', models.IntegerField()),
                ('qty_equal_directory', models.IntegerField()),
                ('qty_at_directory', models.IntegerField()),
                ('qty_and_directory', models.IntegerField()),
                ('qty_exclamation_directory', models.IntegerField()),
                ('qty_space_directory', models.IntegerField()),
                ('qty_tilde_directory', models.IntegerField()),
                ('qty_comma_directory', models.IntegerField()),
                ('qty_plus_directory', models.IntegerField()),
                ('qty_asterisk_directory', models.IntegerField()),
                ('qty_hashtag_directory', models.IntegerField()),
                ('qty_dollar_directory', models.IntegerField()),
                ('qty_percent_directory', models.IntegerField()),
                ('directory_length', models.IntegerField()),
                ('qty_dot_file', models.IntegerField()),
                ('qty_hyphen_file', models.IntegerField()),
                ('qty_underline_file', models.IntegerField()),
                ('qty_slash_file', models.IntegerField()),
                ('qty_questionmark_file', models.IntegerField()),
                ('qty_equal_file', models.IntegerField()),
                ('qty_at_file', models.IntegerField()),
                ('qty_and_file', models.IntegerField()),
                ('qty_exclamation_file', models.IntegerField()),
                ('qty_space_file', models.IntegerField()),
                ('qty_tilde_file', models.IntegerField()),
                ('qty_comma_file', models.IntegerField()),
                ('qty_plus_file', models.IntegerField()),
                ('qty_asterisk_file', models.IntegerField()),
                ('qty_hashtag_file', models.IntegerField()),
                ('qty_dollar_file', models.IntegerField()),
                ('qty_percent_file', models.IntegerField()),
                ('file_length', models.IntegerField()),
                ('qty_dot_params', models.IntegerField()),
                ('qty_hyphen_params', models.IntegerField()),
                ('qty_underline_params', models.IntegerField()),
                ('qty_slash_params', models.IntegerField()),
                ('qty_questionmark_params', models.IntegerField()),
                ('qty_equal_params', models.IntegerField()),
                ('qty_at_params', models.IntegerField()),
                ('qty_and_params', models.IntegerField()),
                ('qty_exclamation_params', models.IntegerField()),
                ('qty_space_params', models.IntegerField()),
                ('qty_tilde_params', models.IntegerField()),
                ('qty_comma_params', models.IntegerField()),
                ('qty_plus_params', models.IntegerField()),
                ('qty_asterisk_params', models.IntegerField()),
                ('qty_hashtag_params', models.IntegerField()),
                ('qty_dollar_params', models.IntegerField()),
                ('qty_percent_params', models.IntegerField()),
                ('params_length', models.IntegerField()),
                ('tld_present_params', models.IntegerField()),
                ('qty_params', models.IntegerField()),
                ('email_in_url', models.IntegerField()),
                ('time_response', models.FloatField()),
                ('domain_spf', models.IntegerField()),
                ('asn_ip', models.IntegerField()),
                ('qty_ip_resolved', models.IntegerField()),
                ('qty_nameservers', models.IntegerField()),
                ('qty_mx_servers', models.IntegerField()),
                ('ttl_hostname', models.IntegerField()),
                ('tls_ssl_certificate', models.IntegerField()),
                ('qty_redirects', models.IntegerField()),
                ('url_google_index', models.IntegerField()),
                ('domain_google_index', models.IntegerField()),
                ('url_shortened', models.IntegerField()),
                ('time_domain_activation', models.IntegerField()),
                ('time_domain_expiration', models.IntegerField()),
                ('phishing', models.JSONField(default=list)),
                ('legit', models.JSONField(default=list)),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('email', models.EmailField(max_length=254)),
                ('password', models.CharField(max_length=10)),
            ],
        ),
    ]

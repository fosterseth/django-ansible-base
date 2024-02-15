# Generated by Django 4.2.6 on 2023-11-20 20:48

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        migrations.swappable_dependency(settings.ANSIBLE_BASE_TEAM_MODEL),
        migrations.swappable_dependency(settings.ANSIBLE_BASE_PERMISSION_MODEL),
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='RoleDefinition',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.TextField(db_index=True, unique=True)),
                ('description', models.TextField(blank=True)),
                ('managed', models.BooleanField(default=False, editable=False)),
                ('permissions', models.ManyToManyField(to=settings.ANSIBLE_BASE_PERMISSION_MODEL)),
                ('content_type', models.ForeignKey(
                    default=None,
                    help_text='Type of resource this can apply to, only used for validation and user assistance',
                    null=True,
                    on_delete=django.db.models.deletion.CASCADE,
                    to='contenttypes.contenttype'
                )),
                ('created_by', models.ForeignKey(
                    default=None,
                    editable=False,
                    help_text='The user who created this resource',
                    null=True,
                    on_delete=django.db.models.deletion.DO_NOTHING,
                    related_name='%(app_label)s_%(class)s_created+',
                    to=settings.AUTH_USER_MODEL
                )),
                ('created_on', models.DateTimeField(default=None, editable=False, help_text='The date/time this resource was created'),),
                ('modified_by', models.ForeignKey(
                    default=None,
                    editable=False,
                    help_text='The user who last modified this resource',
                    null=True,
                    on_delete=django.db.models.deletion.DO_NOTHING,
                    related_name='%(app_label)s_%(class)s_modified+',
                    to=settings.AUTH_USER_MODEL
                )),
                ('modified_on', models.DateTimeField(default=None, editable=False, help_text='The date/time this resource was created'),),
            ],
            options={
                'verbose_name_plural': 'role_definition',
            },
        ),
        migrations.CreateModel(
            name='RoleTeamAssignment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_on', models.DateTimeField(default=django.utils.timezone.now, editable=False, help_text='The date/time this resource was created')),
                ('content_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='contenttypes.contenttype')),
                ('object_id', models.TextField(null=False)),
                ('role_definition', models.ForeignKey(
                    help_text='The role definition which defines permissions conveyed by this assignment', on_delete=django.db.models.deletion.CASCADE,
                    related_name='team_assignments', to='dab_rbac.roledefinition')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.AddField(
            model_name='roleteamassignment',
            name='created_by',
            field=models.ForeignKey(
                default=None,
                editable=False,
                help_text='The user who created this resource',
                null=True,
                on_delete=django.db.models.deletion.DO_NOTHING,
                related_name='%(app_label)s_%(class)s_created+',
                to=settings.AUTH_USER_MODEL
            ),
        ),
        migrations.AddField(
            model_name='roleteamassignment',
            name='team',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.ANSIBLE_BASE_TEAM_MODEL),
        ),
        migrations.CreateModel(
            name='RoleUserAssignment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_on', models.DateTimeField(default=django.utils.timezone.now, editable=False, help_text='The date/time this resource was created')),
                ('content_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='contenttypes.contenttype')),
                ('object_id', models.TextField(null=False)),
                ('role_definition', models.ForeignKey(
                    help_text='The role definition which defines permissions conveyed by this assignment', on_delete=django.db.models.deletion.CASCADE,
                    related_name='user_assignments', to='dab_rbac.roledefinition')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.AddField(
            model_name='roleuserassignment',
            name='created_by',
            field=models.ForeignKey(
                default=None,
                editable=False,
                help_text='The user who created this resource',
                null=True,
                on_delete=django.db.models.deletion.DO_NOTHING,
                related_name='%(app_label)s_%(class)s_created+',
                to=settings.AUTH_USER_MODEL
            ),
        ),
        migrations.AddField(
            model_name='roleuserassignment',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.CreateModel(
            name='ObjectRole',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('object_id', models.TextField(null=False)),
                ('content_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='contenttypes.contenttype')),
                ('provides_teams', models.ManyToManyField(
                    help_text='Users who have this role obtain member access to these teams, and inherit all their permissions',
                    related_name='member_roles', to=settings.ANSIBLE_BASE_TEAM_MODEL)),
                ('role_definition', models.ForeignKey(
                    help_text='The role definition which defines what permissions this object role grants', on_delete=django.db.models.deletion.CASCADE,
                    related_name='object_roles', to='dab_rbac.roledefinition')),
            ],
            options={
                'verbose_name_plural': 'object_roles',
                'ordering': ('content_type', 'object_id'),
            },
        ),
        migrations.AddField(
            model_name='roleuserassignment',
            name='object_role',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='dab_rbac.objectrole', editable=False),
        ),
        migrations.AddField(
            model_name='roleteamassignment',
            name='object_role',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='dab_rbac.objectrole', editable=False),
        ),
        migrations.AddField(
            model_name='objectrole',
            name='teams',
            field=models.ManyToManyField(
                help_text='Teams or groups who have access to the permissions defined by this object role',
                related_name='has_roles',
                through='dab_rbac.RoleTeamAssignment',
                through_fields=("object_role", "team"),
                to=settings.ANSIBLE_BASE_TEAM_MODEL
            ),
        ),
        migrations.AddField(
            model_name='objectrole',
            name='users',
            field=models.ManyToManyField(
                help_text='Users who have access to the permissions defined by this object role',
                related_name='has_roles',
                through='dab_rbac.RoleUserAssignment',
                through_fields=("object_role", "user"),
                to=settings.AUTH_USER_MODEL
            ),
        ),
        migrations.CreateModel(
            name='RoleEvaluation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('codename', models.TextField(help_text='The name of the permission, giving the action and the model, from the Django Permission model')),
                ('content_type_id', models.PositiveIntegerField()),
                ('object_id', models.PositiveIntegerField(null=False)),
            ],
            options={
                'verbose_name_plural': 'role_object_permissions',
            },
        ),
        migrations.AddIndex(
            model_name='objectrole',
            index=models.Index(fields=['content_type', 'object_id'], name='dab_rbac_ob_content_cbd55d_idx'),
        ),
        migrations.AddConstraint(
            model_name='objectrole',
            constraint=models.UniqueConstraint(fields=('object_id', 'content_type', 'role_definition'), name='one_object_role_per_object_and_role'),
        ),
        migrations.AddField(
            model_name='roleevaluation',
            name='role',
            field=models.ForeignKey(
                help_text='The object role that grants this form of permission',
                on_delete=django.db.models.deletion.CASCADE,
                related_name='permission_partials',
                to='dab_rbac.objectrole'
            ),
        ),
        migrations.AddIndex(
            model_name='roleevaluation',
            index=models.Index(fields=['role', 'content_type_id', 'object_id'], name='dab_rbac_ro_role_id_604bc4_idx'),
        ),
        migrations.AddIndex(
            model_name='roleevaluation',
            index=models.Index(fields=['role', 'content_type_id', 'codename'], name='dab_rbac_ro_role_id_8b9faf_idx'),
        ),
        migrations.AddConstraint(
            model_name='roleevaluation',
            constraint=models.UniqueConstraint(fields=('object_id', 'content_type_id', 'codename', 'role'), name='one_entry_per_object_permission_and_role'),
        ),
        migrations.AlterField(
            model_name='objectrole',
            name='provides_teams',
            field=models.ManyToManyField(
                editable=False,
                help_text='Users who have this role obtain member access to these teams, and inherit all their permissions',
                related_name='member_roles',
                to=settings.ANSIBLE_BASE_TEAM_MODEL
            ),
        ),
        migrations.CreateModel(
            name='RoleEvaluationUUID',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('codename', models.TextField(help_text='The name of the permission, giving the action and the model, from the Django Permission model')),
                ('content_type_id', models.PositiveIntegerField()),
                ('object_id', models.UUIDField()),
                ('role', models.ForeignKey(
                    help_text='The object role that grants this form of permission',
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='permission_partials_uuid',
                    to='dab_rbac.objectrole'
                )),
            ],
            options={
                'verbose_name_plural': 'role_object_permissions',
                'indexes': [
                    models.Index(fields=['role', 'content_type_id', 'object_id'], name='dab_rbac_ro_role_id_237936_idx'),
                    models.Index(fields=['role', 'content_type_id', 'codename'], name='dab_rbac_ro_role_id_4fe905_idx')
                ],
            },
        ),
        migrations.AddConstraint(
            model_name='roleevaluationuuid',
            constraint=models.UniqueConstraint(
                fields=('object_id', 'content_type_id', 'codename', 'role'), name='one_entry_per_object_permission_and_role_uuid'),
        ),
        migrations.AlterUniqueTogether(
            name='roleteamassignment',
            unique_together={('team', 'object_role')},
        ),
        migrations.AlterUniqueTogether(
            name='roleuserassignment',
            unique_together={('user', 'object_role')},
        ),
    ]

# Generated by Django 4.2.8 on 2024-01-26 11:03

from django.db import migrations, models


def create_test_data(apps, schema_editor):
    """
    This migration sets up some resource instances after the resource registry is
    created. This is to test two things:
        1. That the post_save and post_delete signals in the resources app do not
           fire during migrations.
        2. That the post migration signal to initialize resource instances from
           existing objects works correctly.
    """
    ResourceMigrationTestModel = apps.get_model("test_app", "ResourceMigrationTestModel")
    Resource = apps.get_model("dab_resource_registry", "Resource")

    ResourceMigrationTestModel.objects.create(name="migration resource")
    r2 = ResourceMigrationTestModel.objects.create(name="migration resource 2")

    assert Resource.objects.all().count() == 0

    r2.delete()


class Migration(migrations.Migration):
    dependencies = [
        ('test_app', '0001_initial'),
        # needs to be a separate migration because of these app dependencies
        ('dab_resource_registry', '__first__'),
        ('dab_rbac', '__first__'),
    ]

    operations = [
        migrations.CreateModel(
            name='ResourceMigrationTestModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
            ],
        ),
        migrations.RunPython(
            code=create_test_data,
            reverse_code=migrations.RunPython.noop
        ),
        migrations.AddField(
            model_name='team',
            name='singleton_roles',
            field=models.ManyToManyField(blank=True, related_name='singleton_teams', to='dab_rbac.roledefinition'),
        ),
        migrations.AddField(
            model_name='user',
            name='singleton_roles',
            field=models.ManyToManyField(blank=True, related_name='singleton_users', to='dab_rbac.roledefinition'),
        ),
    ]
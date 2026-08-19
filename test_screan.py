created = 0

for target in targets:
    for entry in schedule_entries:
        schedule = TaskScheduleDb.objects.create(
            target=target,
            schedule_time=_format_local(schedule_utc),
            schedule_time_utc=schedule_utc,
            last_run_at=None,
            project_id=project_id_value,
            scanner=entry["scanner"],
            scan_type=entry["scan_type"],
            scan_config=entry["scan_config"],
            periodic_task=periodic_task_value,
            created_by=request.user,
            updated_by=request.user,
            organization=request.user.organization,
        )

        schedule.task_id = str(schedule.id)
        schedule.save(update_fields=["task_id"])
        scheduler.register_network_schedule(schedule)
        created += 1

if created:
    messages.success(
        request,
        f"Scheduled {created} network scan{'s' if created != 1 else ''}.",
    )

return HttpResponseRedirect(reverse("networkscanners:net_scan_schedule"))
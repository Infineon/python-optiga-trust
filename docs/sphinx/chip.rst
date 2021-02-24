OPTIGA™ Trust management
========================

Users allowed to read or sometimes change the following properties of the chip

Here are some code example using the API

::

    import optigatrust as optiga

    chip = optiga.Chip()

    chip.current_limit = 15 # allowed are from 6 to 15
    chip.sleep_activation_delay = 255 # allowed are from 0 to 255
    # This might affect your chip, and even lock it, so please make sure you know what you do
    # chip.global_lifecycle_state = 'operational'
    # This is only OPTIGA Trust M3 applicable
    # Disable the security monitor
    chip.config_security_monitor(t_max=0)

    print('New state for parameters')
    print('Current limit : {0}'.format(chip.current_limit))
    print('Sleep Activation Delay : {0}'.format(chip.sleep_activation_delay))
    print('Coprocessor Unique ID : {0}'.format(chip.uid))
    print('Global Lifecycle State (LcsG) : {0}'.format(chip.global_lifecycle_state))
    print('Security Status : {0}'.format(chip.security_status))
    print('Security Event Counter Value : {0}'.format(chip.security_event_counter))



.. autoclass:: optigatrust.Chip
   :members: current_limit, sleep_activation_delay, uid, global_lifecycle_state, security_status, security_event_counter, security_monitor, config_security_monitor

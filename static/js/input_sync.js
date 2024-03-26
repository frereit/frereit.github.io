export function register_synced_inputs() {
    let inputs = document.body.querySelectorAll('input');

    inputs.forEach(input => {
        let classes = Array.from(input.classList);
        let syncClassesInCurrentInput = classes.filter(c => c.startsWith('sync-'));
        if (syncClassesInCurrentInput.length > 1) {
            throw new Error(`Input contains more than one sync class: ${syncClassesInCurrentInput.join(', ')}`);
        }
        if (syncClassesInCurrentInput.length === 0) {
            return;
        }
        let syncClass = syncClassesInCurrentInput[0];
        const update = e => {
            let syncedInputs = document.querySelectorAll(`.${syncClass}`);
            syncedInputs.forEach(syncedInput => {
                if (syncedInput !== e.target) {
                    syncedInput.value = e.target.value;
                }
            });

            let event = new CustomEvent(syncClass, e);
            document.body.dispatchEvent(event);
        };
        input.addEventListener('input', update);
        update({target: input});
    });
}


<script lang="ts">
    import { api, type RdpKnownHostListItem } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import { stringifyError } from 'common/errors'
    import RelativeDate from 'admin/RelativeDate.svelte'

    interface Props {
        id: string
    }

    let { id }: Props = $props()

    let certs: RdpKnownHostListItem[] = $state([])
    let error: string | null = $state(null)
    let loading = $state(true)

    async function loadCerts () {
        try {
            certs = await api.getRdpKnownHosts({ id })
            error = null
        } catch (err) {
            error = await stringifyError(err)
        } finally {
            loading = false
        }
    }

    async function deleteCert (sha256: string) {
        try {
            await api.deleteRdpKnownHost({ id, sha256 })
            await loadCerts()
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    loadCerts()
</script>

<h4>Trusted RDP Certificates</h4>

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

{#if loading}
    <Alert color="secondary">Loading trusted certificates...</Alert>
{:else if certs.length === 0}
    <Alert color="secondary">
        No trusted certificates yet. A certificate will be pinned automatically on first connection (TOFU).
    </Alert>
{:else}
    <div class="certs-list">
        {#each certs as cert (cert.certificateSha256)}
            <div class="cert-item d-flex align-items-center gap-2">
                <div class="cert-info flex-grow-1">
                    <code class="sha256">{cert.certificateSha256}</code>
                    <div class="text-muted small">
                        {cert.host}:{cert.port}
                        &mdash; trusted <RelativeDate date={new Date(cert.created)} />
                    </div>
                </div>
                <AsyncButton
                    color="danger"
                    outline
                    size="sm"
                    click={() => deleteCert(cert.certificateSha256)}
                >
                    Delete
                </AsyncButton>
            </div>
        {/each}
    </div>
{/if}

<style lang="scss">
    .certs-list {
        display: flex;
        flex-direction: column;
        gap: 0.75rem;
    }

    .cert-item {
        padding: 0.5rem 0.75rem;
        border: 1px solid var(--bs-border-color);
        border-radius: 0.375rem;
    }

    .sha256 {
        font-size: 0.8rem;
        word-break: break-all;
    }
</style>

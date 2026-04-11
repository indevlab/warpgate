<script lang="ts">
    import Fa from 'svelte-fa'
    import { onDestroy, onMount } from 'svelte'
    import { faPlay, faPause, faExpand } from '@fortawesome/free-solid-svg-icons'
    import { Spinner } from '@sveltestrap/sveltestrap'
    import formatDuration from 'format-duration'
    import type { Recording } from 'admin/lib/api'

    interface Props {
        recording: Recording
    }

    let { recording }: Props = $props()

    let canvasElement: HTMLCanvasElement
    let rootElement: HTMLDivElement
    let timestamp = $state(0)
    let seekInputValue = $state(0)
    let duration = $state(0)
    let playing = $state(false)
    let loading = $state(true)
    let canvasWidth = $state(1024)
    let canvasHeight = $state(768)

    interface RdpHeader {
        type: 'header'
        version: number
        width: number
        height: number
        started_at: string
        target: { name: string; host: string }
    }

    interface RdpScreenshot {
        type: 'screenshot'
        t: number
        w: number
        h: number
        encoding: string
        data: string
    }

    interface RdpInput {
        type: 'input'
        t: number
        kind: string
        payload: Record<string, unknown>
    }

    type RdpFrame = RdpHeader | RdpScreenshot | RdpInput

    let frames: RdpFrame[] = []
    let currentImage: HTMLImageElement | null = null

    onMount(async () => {
        const url = `/@warpgate/admin/api/recordings/${recording.id}/rdp`
        const response = await fetch(url)
        const text = await response.text()

        for (const line of text.split('\n')) {
            if (!line.trim()) {
                continue
            }
            const frame: RdpFrame = JSON.parse(line)
            frames.push(frame)

            if (frame.type === 'header') {
                canvasWidth = frame.width
                canvasHeight = frame.height
            }
            if (frame.type === 'screenshot' || frame.type === 'input') {
                duration = Math.max(duration, frame.t)
            }
        }

        loading = false
        await seek(0)
    })

    async function loadImage (data: string): Promise<HTMLImageElement> {
        return new Promise((resolve, reject) => {
            const img = new Image()
            img.onload = () => resolve(img)
            img.onerror = reject
            img.src = `data:image/png;base64,${data}`
        })
    }

    function renderFrame (img: HTMLImageElement) {
        const ctx = canvasElement?.getContext('2d')
        if (!ctx) {
            return
        }
        ctx.drawImage(img, 0, 0, canvasElement.width, canvasElement.height)
    }

    async function seek (time: number) {
        let lastScreenshot: RdpScreenshot | null = null

        for (const frame of frames) {
            if (frame.type === 'screenshot') {
                if (frame.t <= time) {
                    lastScreenshot = frame
                } else {
                    break
                }
            }
        }

        if (lastScreenshot) {
            currentImage = await loadImage(lastScreenshot.data)
            renderFrame(currentImage)
        }

        timestamp = time
        if (duration > 0) {
            seekInputValue = 100 * time / duration
        }
    }

    let destroyed = false
    onDestroy(() => { destroyed = true })

    async function step () {
        if (destroyed) {
            return
        }
        if (playing) {
            const next = Math.min(duration, timestamp + 100)
            if (next >= duration) {
                playing = false
            } else {
                await seek(next)
            }
        }
        setTimeout(step, 100)
    }

    function togglePlaying () {
        if (timestamp >= duration) {
            seek(0)
        }
        playing = !playing
    }

    function keyPressHandler (event: KeyboardEvent) {
        if (event.key === ' ') {
            togglePlaying()
        }
    }

    function toggleFullscreen () {
        if (document.fullscreenElement) {
            document.exitFullscreen()
        } else {
            rootElement.requestFullscreen()
        }
    }

    step()
</script>

<div class="root" bind:this={rootElement}>
    {#if loading}
    <Spinner color="primary" />
    {/if}

    {#if !loading && !playing}
    <div class="pause-overlay">
        <Fa icon={faPlay} size="2x" fw />
    </div>
    {/if}

    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <div
        class="canvas-container"
        class:invisible={loading}
        onclick={togglePlaying}
        onkeypress={keyPressHandler}
        role="img"
    >
        <canvas
            bind:this={canvasElement}
            width={canvasWidth}
            height={canvasHeight}
        ></canvas>
    </div>

    <div class="toolbar" class:invisible={loading}>
        <button class="btn btn-link" onclick={togglePlaying}>
            <Fa icon={playing ? faPause : faPlay} fw />
        </button>
        <pre class="timestamp">{ formatDuration(timestamp, { leading: true }) }</pre>
        <input
            class="w-100"
            type="range"
            min="0" max="100" step="0.001"
            style="background-size: {seekInputValue}% 100%;"
            bind:value={seekInputValue}
            oninput={() => seek(duration * seekInputValue / 100)} />
        <button class="btn btn-link" onclick={toggleFullscreen}>
            <Fa icon={faExpand} fw />
        </button>
    </div>
</div>

<style lang="scss">
    .root {
        background: #1a1a2e;
        border-radius: 5px;
        overflow: hidden;
        position: relative;
        contain: content;
        display: flex;
        flex-direction: column;
    }

    .canvas-container {
        padding: 5px;
        margin: auto;
        cursor: pointer;

        canvas {
            max-width: 100%;
            height: auto;
        }
    }

    .toolbar {
        display: flex;
    }

    .btn {
        color: #eee;

        :global(svg) {
            transition: all .25s ease-out;
            &:hover {
                transform: scale(1.2);
            }
        }
    }

    :global(.spinner-border), .pause-overlay {
        position: absolute;
        left: 50%;
        top: 50%;
        margin: -12px 0 0 -12px;
        z-index: 1;
    }

    .pause-overlay {
        width: 24px;
        text-align: center;
        color: white;
    }

    input[type="range"] {
        appearance: none;
        -webkit-appearance: none;
        margin: 18px 10px 0;
        height: 2px;
        background: #ffffff99;
        border-radius: 5px;
        background: linear-gradient(#eee, #eee);
        background-repeat: no-repeat;
        cursor: pointer;

        &:hover::-webkit-slider-thumb {
            transform: scale(1.5);
        }
    }

    input[type="range"]::-webkit-slider-thumb {
        -webkit-appearance: none;
        height: 10px;
        width: 10px;
        border-radius: 50%;
        background: #eee;
        transition: all .25s ease-out;
    }

    input[type=range]::-webkit-slider-runnable-track  {
        -webkit-appearance: none;
        box-shadow: none;
        border: none;
        background: transparent;
    }

    .timestamp {
        flex: none;
        overflow: visible;
        color: #eeeeee;
        margin: 0;
        font-size: 0.75rem;
        align-self: center;
    }
</style>

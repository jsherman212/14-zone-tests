#include <mach/kmod.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

extern uint64_t kernel_slide;

extern void *(*kalloc_external)(vm_size_t sz);
extern void (*kfree_ext)(void *kheap, void *addr, vm_size_t sz);
extern void (*kprintf)(const char *fmt, ...);
extern void *(*_memset)(void *s, int c, size_t n);
extern int (*_snprintf)(char *str, size_t size, const char *fmt, ...);
extern void *(*unified_kalloc)(size_t sz);
extern void (*unified_kfree)(void *ptr);

typedef uint16_t zone_id_t;

typedef struct zone_packed_virtual_address {
    uint32_t packed_address;
} zone_pva_t;

struct zone_map_range {
	vm_offset_t min_address;
	vm_offset_t max_address;
} __attribute__((aligned(2 * sizeof(vm_offset_t))));

struct zone_page_metadata;

typedef struct {
    #define ZONE_ADDR_KIND_COUNT 2
	struct zone_map_range      zi_map_range[ZONE_ADDR_KIND_COUNT];
	struct zone_map_range      zi_meta_range; /* debugging only */
	struct zone_map_range      zi_bits_range; /* bits buddy allocator */

	/*
	 * The metadata lives within the zi_meta_range address range.
	 *
	 * The correct formula to find a metadata index is:
	 *     absolute_page_index - page_index(MIN(zi_map_range[*].min_address))
	 *
	 * And then this index is used to dereference zi_meta_range.min_address
	 * as a `struct zone_page_metadata` array.
	 *
	 * To avoid doing that substraction all the time in the various fast-paths,
	 * zi_meta_base are pre-offset with that minimum page index to avoid redoing
	 * that math all the time.
	 *
	 * Do note that the array might have a hole punched in the middle,
	 * see zone_metadata_init().
	 */
	struct zone_page_metadata *zi_meta_base;
} xnu_zone_info_t;

/* 14.6 */
struct zone_page_metadata {
	/* The index of the zone this metadata page belongs to */
	zone_id_t       zm_index : 11;

	/* Whether `zm_bitmap` is an inline bitmap or a packed bitmap reference */
	uint16_t        zm_inline_bitmap : 1;

	/*
	 * Zones allocate in "chunks" of zone_t::z_chunk_pages consecutive
	 * pages, or zpercpu_count() pages if the zone is percpu.
	 *
	 * The first page of it has its metadata set with:
	 * - 0 if none of the pages are currently wired
	 * - the number of wired pages in the chunk (not scaled for percpu).
	 *
	 * Other pages in the chunk have their zm_chunk_len set to
	 * ZM_SECONDARY_PAGE or ZM_SECONDARY_PCPU_PAGE depending on whether
	 * the zone is percpu or not. For those, zm_page_index holds the
	 * index of that page in the run.
	 */
	uint16_t        zm_chunk_len : 4;
#define ZM_CHUNK_LEN_MAX        0x8
#define ZM_SECONDARY_PAGE       0xe
#define ZM_SECONDARY_PCPU_PAGE  0xf

	union {
#define ZM_ALLOC_SIZE_LOCK      1u
		uint16_t zm_alloc_size; /* first page only */
		uint16_t zm_page_index; /* secondary pages only */
	};
	union {
		uint32_t zm_bitmap;     /* most zones */
		uint32_t zm_bump;       /* permanent zones */
	};

	zone_pva_t      zm_page_next;
	zone_pva_t      zm_page_prev;
};

static zone_pva_t zone_pva_from_addr(vm_address_t addr){
    // cannot use atop() because we want to maintain the sign bit
    return (zone_pva_t){ (uint32_t)((intptr_t)addr >> 14) };
}

static xnu_zone_info_t *zone_info = NULL;

struct zone {
	/*
	 * Readonly / rarely written fields
	 */

	/*
	 * The first 4 fields match a zone_view.
	 *
	 * z_self points back to the zone when the zone is initialized,
	 * or is NULL else.
	 */
	void *z_self;
	void *z_stats;
	const char         *z_name;
	void *z_views;

	void *z_expander;
	void *z_pcpu_cache;

	uint16_t            z_chunk_pages;  /* size used for more memory in pages  */
	uint16_t            z_chunk_elems;  /* count of allocations per chunk */
	uint16_t            z_elems_rsv;    /* maintain a free reserve of elements */
	uint16_t            z_elem_size;    /* size of an element                  */

	uint64_t
	/*
	 * Lifecycle state (Mutable after creation)
	 */
	    z_destroyed        :1,  /* zone is (being) destroyed */
	    z_async_refilling  :1,  /* asynchronous allocation pending? */
	    z_replenish_wait   :1,  /* someone is waiting on the replenish thread */
	    z_expanding_wait   :1,  /* is thread waiting for expansion? */
	    z_expander_vm_priv :1,  /* a vm privileged thread is expanding */

	/*
	 * Security sensitive configuration bits
	 */
	    z_allows_foreign   :1,  /* allow non-zalloc space  */
	    z_destructible     :1,  /* zone can be zdestroy()ed  */
	    kalloc_heap        :2,  /* zone_kheap_id_t when part of a kalloc heap */
	    z_noencrypt        :1,  /* do not encrypt pages when hibernating */
	    z_submap_idx       :2,  /* a Z_SUBMAP_IDX_* value */
	    z_va_sequester     :1,  /* page sequester: no VA reuse with other zones */
	    z_free_zeroes      :1,  /* clear memory of elements on free and assert on alloc */

	/*
	 * Behavior configuration bits
	 */
	    z_percpu           :1,  /* the zone is percpu */
	    z_permanent        :1,  /* the zone allocations are permanent */
	    z_replenishes      :1,  /* uses the async replenish mechanism for VM */
	    z_nocaching        :1,  /* disallow zone caching for this zone */
	    collectable        :1,  /* garbage collect empty pages */
	    exhaustible        :1,  /* merely return if empty? */
	    expandable         :1,  /* expand zone (with message)? */
	    no_callout         :1,

	    _reserved          :26,

	/*
	 * Debugging features
	 */
	    alignment_required :1,  /* element alignment needs to be preserved */
	    gzalloc_tracked    :1,  /* this zone is tracked by gzalloc */
	    gzalloc_exempt     :1,  /* this zone doesn't participate with gzalloc */
	    kasan_fakestacks   :1,
	    kasan_noquarantine :1,  /* whether to use the kasan quarantine */
	    tag_zone_index     :7,
	    tags               :1,
	    tags_inline        :1,
	    zleak_on           :1,  /* Are we collecting allocation information? */
	    zone_logging       :1;  /* Enable zone logging for this zone. */

	/*
	 * often mutated fields
	 */

    struct {
        uintptr_t opaque[2];
    } z_lock;
	/* lck_spin_t          z_lock; */


    struct {
        void *first;
        void **last;
    } z_recirc;
	/* struct zone_depot   z_recirc; */

	/*
	 * Page accounting (wired / VA)
	 *
	 * Those numbers are unscaled for z_percpu zones
	 * (zone_scale_for_percpu() needs to be used to find the true value).
	 */
	uint32_t            z_wired_max;    /* how large can this zone grow        */
	uint32_t            z_wired_hwm;    /* z_wired_cur high watermark          */
	uint32_t            z_wired_cur;    /* number of pages used by this zone   */
	uint32_t            z_wired_empty;  /* pages collectable by GC             */
	uint32_t            z_va_cur;       /* amount of VA used by this zone      */

	/*
	 * list of metadata structs, which maintain per-page free element lists
	 *
	 * Note: Due to the index packing in page metadata,
	 *       these pointers can't be at the beginning of the zone struct.
	 */
	zone_pva_t          z_pageq_empty;  /* populated, completely empty pages   */
	zone_pva_t          z_pageq_partial;/* populated, partially filled pages   */
	zone_pva_t          z_pageq_full;   /* populated, completely full pages    */
	zone_pva_t          z_pageq_va;     /* non-populated VA pages              */

	/*
	 * Zone statistics
	 *
	 * z_contention_wma:
	 *   weighted moving average of the number of contentions per second,
	 *   in Z_CONTENTION_WMA_UNIT units (fixed point decimal).
	 *
	 * z_contention_cur:
	 *   count of recorded contentions that will be fused in z_contention_wma
	 *   at the next period.
	 *
	 * z_recirc_cur:
	 *   number of magazines in the recirculation depot.
	 *
	 * z_elems_free:
	 *   number of free elements in the zone.
	 *
	 * z_elems_{min,max}:
	 *   tracks the low/high watermark of z_elems_free for the current
	 *   weighted moving average period.
	 *
	 * z_elems_free_wss:
	 *   weighted moving average of the (z_elems_free_max - z_elems_free_min)
	 *   amplited which is used by the GC for trim operations.
	 *
	 * z_elems_avail:
	 *   number of elements in the zone (at all).
	 */
#define Z_CONTENTION_WMA_UNIT (1u << 8)
	uint32_t            z_contention_wma;
	uint32_t            z_contention_cur;
	uint32_t            z_recirc_cur;
	uint32_t            z_elems_free_max;
	uint32_t            z_elems_free_wss;
	uint32_t            z_elems_free_min;
	uint32_t            z_elems_free;   /* Number of free elements             */
	uint32_t            z_elems_avail;  /* Number of elements available        */
};

static struct zone *zone_array = NULL;

static vm_offset_t zone_pva_to_addr(zone_pva_t page){
	// cause sign extension so that we end up with the right address
	return (vm_offset_t)(int32_t)page.packed_address << 14;
}

#define ptoa(x) ((vm_address_t)(x) << 14)
static vm_offset_t zone_meta_to_addr(struct zone_page_metadata *meta){
	return ptoa((int32_t)(meta - zone_info->zi_meta_base));
}

static struct zone_page_metadata *zone_pva_to_meta(zone_pva_t page){
    if(!zone_info){
        /* XXX iphone 8 14.6 */
        /* Found by searching for string
         *    zone element pointer validation failed (addr
         * then following first xref
         * go to top of xrefed function
         * you will see ADRL ... LDP ... the dst of the SECOND adrl is zone_info
         */
        zone_info = (xnu_zone_info_t *)(0xFFFFFFF0077296F0 + kernel_slide);
    }

	return &zone_info->zi_meta_base[page.packed_address];
}

static zone_id_t zone_index_from_ptr(const void *kptr){
    zone_pva_t pva = zone_pva_from_addr((vm_offset_t)kptr);
    struct zone_page_metadata *meta = zone_pva_to_meta(pva);
    return meta->zm_index;
}

static struct zone_page_metadata *zone_meta_from_addr(vm_offset_t addr){
	return zone_pva_to_meta(zone_pva_from_addr(addr));
}

static bool zone_pva_is_null(zone_pva_t page){
	return page.packed_address == 0;
}

static bool zone_pva_is_queue(zone_pva_t page){
	// actual kernel pages have the top bit set
	return (int32_t)page.packed_address > 0;
}

static bool zone_pva_is_equal(zone_pva_t pva1, zone_pva_t pva2){
	return pva1.packed_address == pva2.packed_address;
}

void *zone_for_kptr(void *kptr){
    if(!zone_array){
        /* iphone 8 14.6 */
        /* Found in the same place zone_info was found */
        zone_array = (struct zone *)(0xFFFFFFF00939D808 + kernel_slide);
    }

    if(!kptr)
        return NULL;

    zone_id_t zidx = zone_index_from_ptr(kptr);
    return zone_array + zidx;
}

static void zone_page_metadata_dump(struct zone_page_metadata *zpm){
    if(!zpm)
        return;

    void *zpm_page = (void *)zone_meta_to_addr(zpm);

    kprintf("zone page metadata for page %p @ %p:\n", zpm_page, zpm);
    kprintf("\tzm_index:            %d (aka '%s')\n", zpm->zm_index,
            (struct zone *)(zone_array + zpm->zm_index)->z_name);

    if(zpm->zm_chunk_len == ZM_SECONDARY_PAGE ||
            zpm->zm_chunk_len == ZM_SECONDARY_PCPU_PAGE){
        kprintf("\tzm_page_index:       %d", zpm->zm_page_index);

        if(zpm->zm_chunk_len == ZM_SECONDARY_PAGE)
            kprintf("  (ZM_SECONDARY_PAGE)\n");
        else
            kprintf("  (ZM_SECONDARY_PCPU_PAGE)\n");
    }
    else{
        kprintf("\tzm_chunk_len:        %d\n", zpm->zm_chunk_len);
        kprintf("\tzm_alloc_size:       %d\n", zpm->zm_alloc_size);
    }

    void *zm_page_prev_kptr;
    const char *zm_page_prev_str;

    if(zone_pva_is_queue(zpm->zm_page_prev)){
        zm_page_prev_kptr = (void *)zone_pva_to_meta(zpm->zm_page_prev);
        zm_page_prev_str = "queue";
    }
    else{
        zm_page_prev_kptr = (void *)zone_pva_to_addr(zpm->zm_page_prev);
        zm_page_prev_str = "ptr";
    }

    void *zm_page_next_kptr;
    const char *zm_page_next_str;

    if(zone_pva_is_queue(zpm->zm_page_next)){
        zm_page_next_kptr = (void *)zone_pva_to_meta(zpm->zm_page_next);
        zm_page_next_str = "queue";
    }
    else{
        zm_page_next_kptr = (void *)zone_pva_to_addr(zpm->zm_page_next);
        zm_page_next_str = "ptr";
    }

    kprintf("\tzm_page_prev:        %#x     (%p, %s)\n", zpm->zm_page_prev,
            zm_page_prev_kptr, zm_page_prev_str);
    kprintf("\tzm_page_next:        %#x     (%p, %s)\n", zpm->zm_page_next,
            zm_page_next_kptr, zm_page_next_str);
}

static char *g_listbuf = NULL;
static const size_t g_listbuf_len = 0x20000;

static void zlist_dump(zone_pva_t head){
    if(zone_pva_is_null(head)){
        kprintf("\t[empty - zone_pva_is_null(head)]\n");
        return;
    }

    struct zone_page_metadata *meta = (void *)zone_pva_to_meta(head);

    if(!meta)
        return;

    if(!zone_pva_is_queue(meta->zm_page_prev)){
        kprintf("%s: meta prev is not a queue?\n", __func__);
        return;
    }

    size_t i = 0;

    _memset(g_listbuf, 0, g_listbuf_len);
    char *g_listbufp = g_listbuf;

    bool printed_bracket = false;

    for(;;){
        void *page = (void *)zone_meta_to_addr(meta);

        uint16_t chunk_len = meta->zm_chunk_len;

        if(chunk_len == ZM_SECONDARY_PAGE ||
                chunk_len == ZM_SECONDARY_PCPU_PAGE){
            kprintf("**********************BAD CHUNK LEN\n");
        }
        else{
            g_listbufp += _snprintf(g_listbufp, g_listbuf_len, "%p --> ", page);

            for(uint16_t i=1; i<chunk_len; i++){
                void *more = (void *)((uintptr_t)page + (0x4000 * i));
                g_listbufp += _snprintf(g_listbufp, g_listbuf_len, "%p --> ", more);
            }
        }

        if(zone_pva_is_null(meta->zm_page_next))
            break;

        meta = (void *)zone_pva_to_meta(meta->zm_page_next);
        i++;
    }

    kprintf("\t%s[end]\n", g_listbuf);
}

void zinfo_for_kptr(void *kptr){
    if(!g_listbuf){
        g_listbuf = unified_kalloc(g_listbuf_len);

        if(!g_listbuf){
            kprintf("%s: listbuf allocation failed\n", __func__);
            return;
        }

        zone_info = (xnu_zone_info_t *)(0xFFFFFFF0077296F0 + kernel_slide);
    }

    if(!kptr)
        return;

    struct zone *zone = zone_for_kptr(kptr);

    kprintf("zoneinfo for zone '%s':\n", zone->z_name);
    kprintf("\tsequestered?              %d\n", zone->z_va_sequester);
    kprintf("\telem size:                %d\n", zone->z_elem_size);
    kprintf("\tchunk size (in pages):    %d\n", zone->z_chunk_pages);
    kprintf("\telems per chunk:          %d\n", zone->z_chunk_elems);
    kprintf("\tnumber of free elements:  %d\n", zone->z_elems_free);
    kprintf("\tfree reserve elems:       %d\n", zone->z_elems_rsv);
    kprintf("\tper CPU?                  %d\n", zone->z_percpu);
    kprintf("\tcollectable?              %d\n", zone->collectable);
    kprintf("\texpandable?               %d\n", zone->expandable);
    kprintf("\tallows foreign?           %d\n", zone->z_allows_foreign);
    kprintf("\tbzero elems on free?      %d\n", zone->z_free_zeroes);
    kprintf("\n");

    kprintf("empty:\n");
    zlist_dump(zone->z_pageq_empty);

    kprintf("\n");
    kprintf("partial:\n");
    zlist_dump(zone->z_pageq_partial);

    kprintf("\n");
    kprintf("full:\n");
    zlist_dump(zone->z_pageq_full);

    kprintf("\n");
    kprintf("depopulated VA:\n");
    zlist_dump(zone->z_pageq_va);
}

void hookme_hook(void *arg){
    vm_size_t sz = (vm_size_t)arg;

    void *mem = kalloc_external(sz);

    if(!mem){
        kprintf("%s: kalloc_external failed for alloc of size %ld\n",
                __func__, sz);
        return;
    }

    zinfo_for_kptr(mem);
    kfree_ext(NULL, mem, sz);
}

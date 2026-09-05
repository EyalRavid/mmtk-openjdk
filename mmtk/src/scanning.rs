use crate::gc_work::*;
use crate::Slot;
use crate::{NewBuffer, OpenJDKSlot, UPCALLS};
use crate::{OpenJDK, SlotsClosure};
use mmtk::memory_manager;
use mmtk::plan::immix::Pause;
use mmtk::plan::lxr::LXR;
use mmtk::scheduler::RootKind;
use mmtk::util::opaque_pointer::*;
use mmtk::util::{Address, ObjectReference};
use mmtk::vm::ObjectKind;
use mmtk::vm::{RootsWorkFactory, Scanning, SlotVisitor};
use mmtk::Mutator;
use mmtk::MutatorContext;

pub struct VMScanning {}

#[allow(unused)]
pub(crate) const WORK_PACKET_CAPACITY: usize = mmtk::scheduler::EDGES_WORK_BUFFER_SIZE;

extern "C" fn report_slots_and_renew_buffer<S: Slot, F: RootsWorkFactory<S>>(
    ptr: *mut Address,
    length: usize,
    capacity: usize,
    factory_ptr: *mut libc::c_void,
) -> NewBuffer {
    if !ptr.is_null() {
        // Note: Currently OpenJDKSlot has the same layout as Address.  If the layout changes, we
        // should fix the Rust-to-C interface.
        let buf = unsafe { Vec::<S>::from_raw_parts(ptr as _, length, capacity) };
        if cfg!(feature = "roots_breakdown") {
            super::gc_work::record_roots(buf.len());
        }
        let factory: &mut F = unsafe { &mut *(factory_ptr as *mut F) };
        factory.create_process_roots_work(buf, RootKind::Strong);
    }
    let (ptr, _, capacity) = {
        // TODO: Use Vec::into_raw_parts() when the method is available.
        use std::mem::ManuallyDrop;
        let new_vec = Vec::with_capacity(F::BUFFER_SIZE);
        let mut me = ManuallyDrop::new(new_vec);
        (me.as_mut_ptr(), me.len(), me.capacity())
    };
    NewBuffer { ptr, capacity }
}

pub(crate) fn to_slots_closure<S: Slot, F: RootsWorkFactory<S>>(factory: &mut F) -> SlotsClosure {
    SlotsClosure {
        func: report_slots_and_renew_buffer::<S, F>,
        data: factory as *mut F as *mut libc::c_void,
    }
}

impl<const COMPRESSED: bool> Scanning<OpenJDK<COMPRESSED>> for VMScanning {
    fn scan_object(
        tls: VMWorkerThread,
        object: ObjectReference,
        slot_visitor: &mut impl SlotVisitor<OpenJDKSlot<COMPRESSED>>,
    ) {
        crate::object_scanning::scan_object::<COMPRESSED>(object, slot_visitor, tls);
    }

    fn scan_object_with_klass(
        tls: VMWorkerThread,
        object: ObjectReference,
        slot_visitor: &mut impl SlotVisitor<OpenJDKSlot<COMPRESSED>>,
        klass: Address,
    ) {
        crate::object_scanning::scan_object_with_klass::<COMPRESSED>(
            object,
            slot_visitor,
            tls,
            klass,
        );
    }

    fn obj_array_data(o: ObjectReference) -> crate::OpenJDKSlotRange<COMPRESSED> {
        crate::object_scanning::obj_array_data::<COMPRESSED>(unsafe { std::mem::transmute(o) })
    }

    fn is_obj_array(o: ObjectReference) -> bool {
        crate::object_scanning::is_obj_array::<COMPRESSED>(unsafe { std::mem::transmute(o) })
    }

    fn is_val_array(o: ObjectReference) -> bool {
        crate::object_scanning::is_val_array::<COMPRESSED>(unsafe { std::mem::transmute(o) })
    }

    fn get_obj_kind(o: ObjectReference) -> ObjectKind {
        crate::object_scanning::get_obj_kind::<COMPRESSED>(unsafe { std::mem::transmute(o) })
    }

    fn notify_initial_thread_scan_complete(_partial_scan: bool, _tls: VMWorkerThread) {
        // unimplemented!()
        // TODO
    }

    fn scan_roots_in_mutator_thread(
        _tls: VMWorkerThread,
        mutator: &'static mut Mutator<OpenJDK<COMPRESSED>>,
        mut factory: impl RootsWorkFactory<OpenJDKSlot<COMPRESSED>>,
    ) {
        let tls = mutator.get_tls();
        unsafe {
            ((*UPCALLS).scan_roots_in_mutator_thread)(to_slots_closure(&mut factory), tls);
        }
    }

    fn scan_multiple_thread_root(
        _tls: VMWorkerThread,
        mutators: Vec<VMMutatorThread>,
        mut factory: impl RootsWorkFactory<<OpenJDK<COMPRESSED> as mmtk::vm::VMBinding>::VMSlot>,
    ) {
        // let t = if cfg!(feature = "roots_breakdown") {
        //     Some(std::time::SystemTime::now())
        // } else {
        //     None
        // };
        let len = mutators.len();
        let ptr = mutators.as_ptr();
        unsafe {
            ((*UPCALLS).scan_multiple_thread_roots)(
                to_slots_closure(&mut factory),
                std::mem::transmute(ptr),
                len,
            );
        }
        // if cfg!(feature = "roots_breakdown") {
        //     let ms = t.unwrap().elapsed().unwrap().as_micros() as f32 / 1000f32;
        //     eprintln!(" - ScanThreadRoots ({:.3}ms)", ms);
        // }
    }

    fn scan_vm_specific_roots(
        _tls: VMWorkerThread,
        factory: impl RootsWorkFactory<OpenJDKSlot<COMPRESSED>>,
    ) {
        // The weak-processor storage is a WEAK root set: it holds references into the heap that
        // must not, by themselves, keep their targets alive.
        //
        // Every pause except `Pause::FullRC` scans them here like any other root, which
        // increments their targets and therefore pins them. That is deliberately conservative --
        // this collector has no phase in which a weak root could be cleared, so treating them as
        // strong is the only safe option, and it is balanced: the increment applied here is
        // matched by the decrement `process_prev_roots` applies at the next GC.
        //
        // `Pause::FullRC` is different, and is the one pause that can do better. It is
        // stop-the-world and it runs cycle collection, so it can afford the real two-phase weak
        // root protocol: leave these sets unscanned here, let the *previous* GC's increments be
        // decremented as usual by `process_prev_roots`, and resolve them after cycle collection
        // with `WeakProcessor` -- which forwards the survivors and clears the entries whose target
        // reached rc == 0.
        //
        // Skipping the scan is what makes that work. With no increment from this GC and nothing
        // pushed into `curr_roots`, an object held *only* by a weak root reaches rc == 0 during
        // the decrement phase and dies, and trial deletion sees a cycle's true external reference
        // count rather than one inflated by weak edges.
        //
        // The bookkeeping stays balanced across the transition, which is the property to protect:
        //
        //     GC N   (ordinary)  scanned as strong -> incremented -> pushed to `curr_roots`
        //     GC N+1 (FullRC)    `prev_roots` decrements them; not scanned, nothing pushed
        //     GC N+2 (ordinary)  decrements what N+1 pushed (no weak entries); scans them again
        //
        // ONLY `ScanWeakProcessorRoots` may be deferred, and the rule is exact: defer precisely
        // the root sets that `update_weak_processor` cleans up, and no others.
        //
        //     scan_weak_processor_roots -> WeakProcessor::oops_do
        //     mmtk_update_weak_processor-> WeakProcessor::weak_oops_do   <- same storages
        //
        // `ScanStringTableRoots` looks like a weak set and is one, but in JDK 11 the string table
        // is its own `OopStorage` (`StringTable::oops_do`) and is NOT part of `WeakProcessor`'s
        // set.  Deferring it removes what keeps interned strings alive while nothing clears or
        // forwards the table's entries, so they are left pointing at freed objects and the next
        // intern lookup dereferences one -- a SIGSEGV inside `java_lang_String::equals`, observed
        // 2026-09-04.  Clearing the string table needs `StringTable::unlink` with an is-alive
        // closure, which is separate work; until then it stays a strong root.
        //
        // `ScanClassLoaderDataGraphRoots` likewise stays in every pause: genuinely mixed
        // strong/weak, and separating it is tied to class unloading, which this fork
        // does not perform.
        //
        // `ScanCodeCacheRoots` stays in every pause too, and it is the one the rule above catches
        // that is least obvious.  It reaches `CodeCache::blobs_do` with a `MarkingCodeBlobClosure`
        // (`MMTkHeap::scan_code_cache_roots`), i.e. the oops embedded in compiled methods -- class
        // mirrors, string literals, inlined constants.  Those are STRONG roots in JDK 11 with
        // class unloading off, which is how this fork runs, and `WeakProcessor::weak_oops_do`
        // does not touch them: it is exactly
        //     JNIHandles + JvmtiExport + SystemDictionary::vm_weak_oop_storage + JFR
        // (`weakProcessor.cpp`).  Nothing else forwards them either -- the binding exports
        // `nmethod_fix_relocation`, but mmtk-core has no call site for it.  So deferring this set
        // would remove BOTH the increment that keeps those objects alive AND the only thing that
        // rewrites an nmethod's oop when its target is evacuated, and compiled code would then
        // dereference freed or stale memory.  A build that deferred it was used briefly on
        // 2026-09-04 to try to price batik's retention against the code cache; it produced no
        // usable number, because the residue it needed to measure only accumulates at boundaries
        // the run cannot safely reach.  Pricing a root set's retention needs a per-root-set
        // transitive closure, not a de-pinning.
        let defer_weak_roots = crate::singleton::<COMPRESSED>()
            .get_plan()
            .downcast_ref::<LXR<OpenJDK<COMPRESSED>>>()
            .map(|lxr| lxr.current_pause() == Some(Pause::FullRC))
            .unwrap_or(false);

        let mut w = vec![
            Box::new(ScanUniverseRoots::new(factory.clone())) as _,
            Box::new(ScanJNIHandlesRoots::new(factory.clone())) as _,
            Box::new(ScanObjectSynchronizerRoots::new(factory.clone())) as _,
            Box::new(ScanManagementRoots::new(factory.clone())) as _,
            Box::new(ScanJvmtiExportRoots::new(factory.clone())) as _,
            Box::new(ScanAOTLoaderRoots::new(factory.clone())) as _,
            Box::new(ScanSystemDictionaryRoots::new(factory.clone())) as _,
            Box::new(ScanCodeCacheRoots::new(factory.clone())) as _,
            Box::new(ScanStringTableRoots::new(factory.clone())) as _,
            Box::new(ScanClassLoaderDataGraphRoots::new(factory.clone())) as _,
            Box::new(ScanVMThreadRoots::new(factory.clone())) as _,
        ];
        // The one deferrable set, and the only one: `update_weak_processor` visits exactly the
        // storages this scans, so an entry it leaves unpinned is an entry that pass will either
        // forward or clear.  See the rule above before adding anything to this block.
        if !defer_weak_roots {
            w.push(Box::new(ScanWeakProcessorRoots::new(factory.clone())) as _);
        }
        memory_manager::add_work_packets(
            crate::singleton::<COMPRESSED>(),
            factory.roots_stage(),
            w,
        );
    }

    fn supports_return_barrier() -> bool {
        unimplemented!()
    }

    fn prepare_for_roots_re_scanning() {
        unsafe {
            ((*UPCALLS).prepare_for_roots_re_scanning)();
        }
    }
}

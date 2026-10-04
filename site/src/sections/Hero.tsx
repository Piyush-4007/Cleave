import { motion } from "framer-motion";
import { ArrowRight, ArrowUpRight } from "lucide-react";
import { AccountGraph } from "@/components/AccountGraph";
import { Button } from "@/components/primitives";
import { useGetCleave } from "@/components/GetCleave";

export function Hero() {
  const { getCleave } = useGetCleave();
  return (
    <section id="top" className="relative px-4 pb-16 pt-10 sm:px-6 md:pt-16">
      <div className="mx-auto max-w-7xl">
        <motion.a
          href="#product"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="group inline-flex items-center gap-2 rounded-full border border-ink/15 bg-paper-2/60 py-1 pl-1 pr-3 text-sm text-mute transition-colors hover:border-ink/40"
        >
          <span className="rounded-full bg-ink px-2.5 py-0.5 font-mono text-[11px] font-medium text-lime">v0.7</span>
          Now reads 20 AWS services and runs 46 checks
          <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-0.5" aria-hidden />
        </motion.a>

        <h1 className="display mt-8 text-[clamp(56px,11.5vw,172px)]">
          <motion.span
            className="block"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
          >
            Find the path.
          </motion.span>
          <motion.span
            className="block"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.08, ease: [0.16, 1, 0.3, 1] }}
          >
            Make the{" "}
            <span className="cleaved" data-text="cut.">
              cut.
              <span className="slash" aria-hidden />
            </span>
          </motion.span>
        </h1>

        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.25 }}
          className="mt-10 grid gap-8 md:grid-cols-[1fr_auto] md:items-end"
        >
          <p className="max-w-xl text-xl leading-relaxed text-mute text-pretty">
            Cleave is open-source attack-path analysis for AWS. It maps how your resources and permissions connect,
            finds the routes an attacker could <span className="text-ink">actually walk</span> to admin, and names the{" "}
            <span className="mark text-ink">one change that breaks the most of them.</span>
          </p>
          <div className="flex flex-wrap gap-3">
            <Button onClick={getCleave}>
              Get Cleave, it's free <ArrowUpRight className="size-4 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" aria-hidden />
            </Button>
            <Button href="#watch" variant="outline">
              Watch it work
            </Button>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.35, ease: [0.16, 1, 0.3, 1] }}
          className="mt-14"
        >
          <AccountGraph />
        </motion.div>
      </div>
    </section>
  );
}

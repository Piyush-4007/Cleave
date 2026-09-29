import { Nav } from "./components/Nav";
import { Hero } from "./sections/Hero";
import { Stats } from "./sections/Stats";
import { Problem } from "./sections/Problem";
import { PathShowcase } from "./sections/PathShowcase";
import { Method } from "./sections/Method";
import { WhatItCatches } from "./sections/WhatItCatches";
import { Trust } from "./sections/Trust";
import { Compare } from "./sections/Compare";
import { GetStarted } from "./sections/GetStarted";
import { Footer } from "./sections/Footer";

export function Landing() {
  return (
    <>
      <Nav />
      <main>
        <Hero />
        <Stats />
        <Problem />
        <PathShowcase />
        <Method />
        <WhatItCatches />
        <Trust />
        <Compare />
        <GetStarted />
      </main>
      <Footer />
    </>
  );
}

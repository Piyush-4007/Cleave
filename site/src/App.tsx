import { Nav } from "./sections/Nav";
import { Hero } from "./sections/Hero";
import { Ticker } from "./sections/Ticker";
import { Problem } from "./sections/Problem";
import { Product } from "./sections/Product";
import { How } from "./sections/How";
import { Why } from "./sections/Why";
import { Security } from "./sections/Security";
import { Faq } from "./sections/Faq";
import { Compare } from "./sections/Compare";
import { Engine } from "./sections/Engine";
import { Cta } from "./sections/Cta";

export default function App() {
  return (
    <>
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[60] focus:rounded-full focus:bg-ink focus:px-4 focus:py-2 focus:text-lime"
      >
        Skip to content
      </a>
      <Nav />
      <main id="main">
        <Hero />
        <Ticker />
        <Problem />
        <Product />
        <How />
        <Why />
        <Security />
        <Faq />
        <Compare />
        <Engine />
        <Cta />
      </main>
    </>
  );
}

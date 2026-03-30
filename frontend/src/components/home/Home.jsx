import "./Home.scss";

import React from "react";
import { Container } from "reactstrap";

import { ContentSection } from "@certego/certego-ui";

import { PUBLIC_URL, VERSION } from "../../constants/environment";
import SystemUpdatePanel from "../common/SystemUpdatePanel";

// constants
const versionText = VERSION;
const logoBgImg = `url('${PUBLIC_URL}/logo-negative.png')`;
const blogPosts = [
  {
    title: "IntelOwl: Open-source threat intelligence management",
    subText: "HelpNetSecurity: Interview with Matteo Lodi",
    date: "14th August 2024",
    link: "https://www.helpnetsecurity.com/2024/08/14/intelowl-open-source-threat-intelligence-management/",
  },
  {
    title: "IntelOwl: Making the life of cyber security analysts easier",
    subText: "FIRSTCON24 Fukuoka Talk with Matteo Lodi and Simone Berni",
    date: "10th June 2024",
    link: "https://www.youtube.com/watch?v=1L5rzvlRjdU",
  },
  {
    title: "From Zero to IntelOwl!",
    subText: "The Honeynet Workshop: Denmark 2024",
    date: "29th May 2024",
    link: "https://github.com/intelowlproject/thp_workshop_2024",
  },
  {
    title: "New year, new tool: Intel Owl",
    subText: "Certego Blog: First announcement",
    date: "2nd January 2020",
    link: "https://www.certego.net/en/news/new-year-new-tool-intel-owl/",
  },
];

// Component
export default function Home() {
  console.debug("Home rendered!");

  return (
    <>
      {/* BG Image */}
      <Container fluid id="home__bgImg" style={{ backgroundImage: logoBgImg }}>
        <h2
          id="home__versionText"
          className="text-accent"
          data-glitch={versionText}
        >
          {versionText}
        </h2>
      </Container>
      {/* Content */}
      <Container id="home__content" className="mt-2">
        <ContentSection className="bg-body shadow lead">
          Intel Owl is an Open Source Intelligence, or OSINT solution to get
          threat intelligence data about a specific file, an IP or a domain from
          a single API at scale. It integrates a number of analyzers available
          online and a lot of cutting-edge malware analysis tools. It is for
          everyone who needs a single point to query for info about a specific
          file or observable.
        </ContentSection>
        <br />
        {/* System update notification */}
        <div className="home-update-notice">
          <SystemUpdatePanel compact />
        </div>
        {/* blogposts */}
        <h5 className="text-gradient">IntelOwl News</h5>
        <ContentSection>
          {blogPosts.map(({ title, subText, date, link }) => (
            <ContentSection key={title} className="border-dark bg-body">
              <small className="text-muted float-end">{date}</small>
              <h5 className="text-secondary">{title}</h5>
              <p className="mb-2 text-muted">{subText}</p>
              <a
                className="link-ul-primary"
                href={link}
                target="_blank"
                rel="noopener noreferrer"
              >
                Read
              </a>
            </ContentSection>
          ))}
        </ContentSection>
      </Container>
    </>
  );
}

import "./Home.scss";

import React from "react";
import { Container } from "reactstrap";

import { ContentSection } from "@certego/certego-ui";

import { PUBLIC_URL, VERSION } from "../../constants/environment";

// constants
const versionText = VERSION;
const logoBgImg = `url('${PUBLIC_URL}/logo-negative.png')`;
const blogPosts = [
  {
    title: "IntelOwl: Release v3.0.0",
    subText: "Honeynet Blog: v3.0.0 Announcement",
    date: "13th September 2021",
    link: "https://www.honeynet.org/2021/09/13/intel-owl-release-v3-0-0/",
  },
  {
    title:
      "Intel Owl – OSINT tool automates the intel-gathering process using a single API",
    subText: "Daily Swig: Interview with Matteo Lodi and Eshaan Bansal",
    date: "18th August 2020",
    link: "https://portswigger.net/daily-swig/intel-owl-osint-tool-automates-the-intel-gathering-process-using-a-single-api",
  },
  {
    title: "IntelOwl: Release v1.0.0",
    subText: "Honeynet Blog: v1.0.0 Announcement",
    date: "5th July 2020",
    link: "https://www.honeynet.org/2020/07/05/intel-owl-release-v1-0-0/",
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
      <Container fluid id="home__bgImg" style={{ backgroundImage: logoBgImg, }}>
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
          a single API at scale.
        </ContentSection>
        <br />
        {/* blogposts */}
        <h5 className="text-gradient">IntelOwl News</h5>
        <ContentSection>
          {blogPosts.map(({ title, subText, date, link, }) => (
            <ContentSection key={title} className="border-dark bg-body">
              <small className="text-muted float-right">{date}</small>
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
